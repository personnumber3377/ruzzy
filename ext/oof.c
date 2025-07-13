#include <dlfcn.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include <ruby.h>
#include <ruby/debug.h>

// This constant is defined in the Ruby C implementation, but it's internal
// only. Fortunately the event hooking still respects this constant being
// passed from an external source. For more information see:
// https://github.com/ruby/ruby/blob/v3_3_0/vm_core.h#L2182-L2184
#define RUBY_EVENT_COVERAGE_BRANCH 0x020000

// 128 arguments should be enough for anybody
#define MAX_ARGS_SIZE 128

// TODO: should we mmap like Atheris?
#define MAX_COUNTERS 8192

extern int LLVMFuzzerRunDriver(
    int *argc,
    char ***argv,
    int (*cb)(const uint8_t *data, size_t size)
);

extern void __sanitizer_cov_8bit_counters_init(uint8_t *start, uint8_t *stop);
extern void __sanitizer_cov_pcs_init(uint8_t *pcs_beg, uint8_t *pcs_end);
extern void __sanitizer_cov_trace_cmp8(uint64_t arg1, uint64_t arg2);
extern void __sanitizer_cov_trace_div8(uint64_t val);

struct PCTableEntry {
  void *pc;
  long flags;
};

struct PCTableEntry PCTABLE[MAX_COUNTERS];
uint8_t COUNTERS[MAX_COUNTERS];
uint32_t COUNTER = 0;
VALUE PROC_HOLDER = Qnil;

static VALUE c_libfuzzer_is_loaded(VALUE self)
{
    void *self_lib = dlopen(NULL, RTLD_LAZY);

    if (!self_lib) {
        return Qfalse;
    }

    void *sym = dlsym(self_lib, "LLVMFuzzerRunDriver");

    dlclose(self_lib);

    return sym ? Qtrue : Qfalse;
}

int ATEXIT_RETCODE = 0;

__attribute__((__noreturn__)) static void ruzzy_exit()
{
     _exit(ATEXIT_RETCODE);
}

__attribute__((__noreturn__)) static void graceful_exit(int code)
{
    // Disable libFuzzer's atexit
    ATEXIT_RETCODE = code;
    atexit(ruzzy_exit);
    exit(code);
}

__attribute__((__noreturn__)) static void sigint_handler(int signal)
{
    fprintf(
        stderr,
        "Signal %d (%s) received. Exiting...\n",
        signal,
        strsignal(signal)
    );
    graceful_exit(signal);
}

static int proc_caller(const uint8_t *data, size_t size)
{
    VALUE arg = rb_str_new((char *)data, size);
    VALUE rb_args = rb_ary_new3(1, arg);
    VALUE result = rb_proc_call(PROC_HOLDER, rb_args);

    // By default, Ruby procs and lambdas will return nil if an explicit return
    // is not specified. Rather than forcing callers to specify a return, let's
    // handle the nil case for them and continue adding the input to the corpus.
    if (NIL_P(result)) {
        // https://llvm.org/docs/LibFuzzer.html#rejecting-unwanted-inputs
        return 0;
    }

    if (!FIXNUM_P(result)) {
        rb_raise(
            rb_eTypeError,
            "fuzz target function did not return an integer or nil"
        );
    }

    return FIX2INT(result);
}

static VALUE c_fuzz(VALUE self, VALUE test_one_input, VALUE args)
{
    char *argv[MAX_ARGS_SIZE];
    int args_len = RARRAY_LEN(args);

    // Assume caller always passes in at least the program name as args[0]
    if (args_len <= 0) {
        rb_raise(
            rb_eRuntimeError,
            "zero arguments passed, we assume at least the program name is present"
        );
    }

    // Account for NULL byte at the end
    if ((args_len + 1) >= MAX_ARGS_SIZE) {
        rb_raise(
            rb_eRuntimeError,
            "cannot specify %d or more arguments",
            MAX_ARGS_SIZE
        );
    }

    if (!rb_obj_is_proc(test_one_input)) {
        rb_raise(rb_eRuntimeError, "expected a proc or lambda");
    }

    PROC_HOLDER = test_one_input;

    for (int i = 0; i < args_len; i++) {
        VALUE arg = RARRAY_PTR(args)[i];
        argv[i] = StringValuePtr(arg);
    }
    argv[args_len] = NULL;

    char **args_ptr = &argv[0];

    // https://llvm.org/docs/LibFuzzer.html#using-libfuzzer-as-a-library
    int result = LLVMFuzzerRunDriver(&args_len, &args_ptr, proc_caller);

    return INT2FIX(result);
}

static VALUE c_trace_cmp8(VALUE self, VALUE arg1, VALUE arg2) {
    // Ruby numerics include both integers and floats. Integers are further
    // divided into fixnums and bignums. Fixnums can be 31-bit or 63-bit
    // integers depending on the bit size of a long. Bignums are arbitrary
    // precision integers. This function can only handle fixnums because
    // sancov only provides comparison tracing up to 8-byte integers.
    if (FIXNUM_P(arg1) && FIXNUM_P(arg2)) {
        long arg1_val = NUM2LONG(arg1);
        long arg2_val = NUM2LONG(arg2);
        __sanitizer_cov_trace_cmp8((uint64_t) arg1_val, (uint64_t) arg2_val);
    }

    return Qnil;
}

static VALUE c_trace_div8(VALUE self, VALUE val) {
    if (FIXNUM_P(val)) {
        long val_val = NUM2LONG(val);
        __sanitizer_cov_trace_div8((uint64_t) val_val);
    }

    return Qnil;
}

static void event_hook_branch(VALUE counter_hash, rb_trace_arg_t *tracearg) {
    VALUE path = rb_tracearg_path(tracearg);
    ID path_sym = rb_intern_str(path);
    VALUE lineno = rb_tracearg_lineno(tracearg);
    VALUE tuple = rb_ary_new_from_args(2, INT2NUM(path_sym), lineno);
    VALUE existing_counter = rb_hash_lookup(counter_hash, tuple);

    int counter_index;

    if (NIL_P(existing_counter)) {
        rb_hash_aset(counter_hash, tuple, INT2FIX(COUNTER));
        counter_index = COUNTER++;
    } else {
        counter_index = FIX2INT(existing_counter);
    }

    COUNTERS[counter_index % MAX_COUNTERS]++;
}

static void enable_branch_coverage_hooks()
{
    // Call Coverage.start(branches: true) to activate branch coverage hooks.
    // Branch coverage hooks will not be activated without this call despite
    // adding the event hooks. I suspect rb_set_coverages must be called
    // first, which initializes some global state that we do not have direct
    // access to. Calling start initializes coverage state here:
    // https://github.com/ruby/ruby/blob/v3_3_0/ext/coverage/coverage.c#L112-L120
    // If rb_set_coverages is not called, then rb_get_coverages returns a NULL
    // pointer, which appears to effectively disable coverage collection here:
    // https://github.com/ruby/ruby/blob/v3_3_0/iseq.c
    rb_require("coverage");
    VALUE coverage_mod = rb_const_get(rb_cObject, rb_intern("Coverage"));
    VALUE hash_arg = rb_hash_new();
    rb_hash_aset(hash_arg, ID2SYM(rb_intern("branches")), Qtrue);
    rb_funcall(coverage_mod, rb_intern("start"), 1, hash_arg);
}

static VALUE c_trace(VALUE self, VALUE harness_path)
{
    VALUE counter_hash = rb_hash_new();

    __sanitizer_cov_8bit_counters_init(COUNTERS, COUNTERS + MAX_COUNTERS);
    __sanitizer_cov_pcs_init((uint8_t *)PCTABLE, (uint8_t *)(PCTABLE + MAX_COUNTERS));

    rb_event_flag_t events = RUBY_EVENT_COVERAGE_BRANCH;
    rb_event_hook_flag_t flags = (
        RUBY_EVENT_HOOK_FLAG_SAFE | RUBY_EVENT_HOOK_FLAG_RAW_ARG
    );
    rb_add_event_hook2(
        (rb_event_hook_func_t) event_hook_branch,
        events,
        counter_hash,
        flags
    );

    enable_branch_coverage_hooks();

    return rb_require(StringValueCStr(harness_path));
}

void Init_cruzzy()
{
    if (signal(SIGINT, sigint_handler) == SIG_ERR) {
        fprintf(stderr, "Could not set SIGINT signal handler\n");
        exit(1);
    }

    VALUE ruzzy = rb_const_get(rb_cObject, rb_intern("Ruzzy"));
    rb_define_module_function(ruzzy, "c_fuzz", &c_fuzz, 2);
    rb_define_module_function(ruzzy, "c_libfuzzer_is_loaded", &c_libfuzzer_is_loaded, 0);
    rb_define_module_function(ruzzy, "c_trace_cmp8", &c_trace_cmp8, 2);
    rb_define_module_function(ruzzy, "c_trace_div8", &c_trace_div8, 1);
    rb_define_module_function(ruzzy, "c_trace", &c_trace, 1);
}


/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <Python.h>

static void LLVMFuzzerFinalizePythonModule();
static void LLVMFuzzerInitPythonModule();
// LLVMFuzzerInitPythonModul
int LLVMFuzzerInitialize(int *argc, char ***argv) {
 // ReadAndMaybeModify(argc, argv);
 LLVMFuzzerInitPythonModule(); // Init the python module shit...
 return 0;
}


static PyObject* py_module = NULL;
/*
class LLVMFuzzerPyContext {
  public:
    LLVMFuzzerPyContext() {
      if (!py_module) {
        LLVMFuzzerInitPythonModule();
      }
    }
    ~LLVMFuzzerPyContext() {
      if (py_module) {
        LLVMFuzzerFinalizePythonModule();
      }
    }
};
*/

// This takes care of (de)initializing things properly
// LLVMFuzzerPyContext init;

static void py_fatal_error() {
  fprintf(stderr, "The libFuzzer Python layer encountered a critical error.\n");
  fprintf(stderr, "Please fix the messages above and then restart fuzzing.\n");
  exit(1);
}



static PyObject* py_functions[2];

// Forward-declare the libFuzzer's mutator callback.
size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);

// This function unwraps the Python arguments passed, which must be
//
// 1) A bytearray containing the data to be mutated
// 2) An int containing the maximum size of the new mutation
//
// The function will modify the bytearray in-place (and resize it accordingly)
// if necessary. It returns None.
PyObject* LLVMFuzzerMutatePyCallback(PyObject* data, PyObject* args) {
  PyObject* py_value;

  // Get MaxSize first, so we know how much memory we need to allocate
  py_value = PyTuple_GetItem(args, 1);
  if (!py_value) {
    fprintf(stderr, "Error: Missing MaxSize argument to native callback.\n");
    py_fatal_error();
  }
  size_t MaxSize = PyLong_AsSize_t(py_value);
  if (MaxSize == (size_t)-1 && PyErr_Occurred()) {
    PyErr_Print();
    fprintf(stderr, "Error: Failed to convert MaxSize argument to size_t.\n");
    py_fatal_error();
  }

  // Now get the ByteArray with our data and resize it appropriately
  py_value = PyTuple_GetItem(args, 0);
  size_t Size = (size_t)PyByteArray_Size(py_value);
  if (PyByteArray_Resize(py_value, MaxSize) < 0) {
    fprintf(stderr, "Error: Failed to resize ByteArray to MaxSize.\n");
    py_fatal_error();
  }

  // Call libFuzzer's native mutator
  size_t RetLen =
    LLVMFuzzerMutate((uint8_t *)PyByteArray_AsString(py_value), Size, MaxSize);

  if (PyByteArray_Resize(py_value, RetLen) < 0) {
    fprintf(stderr, "Error: Failed to resize ByteArray to RetLen.\n");
    py_fatal_error();
  }

  Py_RETURN_NONE;
}

static PyMethodDef LLVMFuzzerMutatePyMethodDef = {
  "LLVMFuzzerMutate",
  LLVMFuzzerMutatePyCallback,
  METH_VARARGS | METH_STATIC,
  NULL
};

static void LLVMFuzzerInitPythonModule() {
  Py_Initialize();
  char* module_name = getenv("LIBFUZZER_PYTHON_MODULE");

  if (module_name) {
    PyObject* py_name = PyUnicode_FromString(module_name);

    py_module = PyImport_Import(py_name);
    Py_DECREF(py_name);

    if (py_module != NULL) {
      py_functions[0] =
        PyObject_GetAttrString(py_module, "custom_mutator");
      py_functions[1] =
        PyObject_GetAttrString(py_module, "custom_crossover");

      if (!py_functions[0]
        || !PyCallable_Check(py_functions[0])) {
        if (PyErr_Occurred())
          PyErr_Print();
        fprintf(stderr, "Error: Cannot find/call custom mutator function in"
                        " external Python module.\n");
        py_fatal_error();
      }

      if (!py_functions[1]
        || !PyCallable_Check(py_functions[1])) {
        if (PyErr_Occurred())
          PyErr_Print();
        fprintf(stderr, "Warning: Python module does not implement crossover"
                        " API, standard crossover will be used.\n");
        py_functions[1] = NULL;
      }
    } else {
      if (PyErr_Occurred())
        PyErr_Print();
      fprintf(stderr, "Error: Failed to load external Python module \"%s\"\n",
        module_name);
      py_fatal_error();
    }
  } else {
    fprintf(stderr, "Warning: No Python module specified, using the default libfuzzer mutator (for now).\n");
    // py_fatal_error();
  }


}

static void LLVMFuzzerFinalizePythonModule() {
  if (py_module != NULL) {
    uint32_t i;
    for (i = 0; i < 2; ++i)
      Py_XDECREF(py_functions[i]);
    Py_DECREF(py_module);
  }
  Py_Finalize();
}

size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
                                          size_t MaxSize, unsigned int Seed) {
  // First check if the custom python mutator is specified:
  if (!py_module) { // No custom python mutator, so therefore just mutate regularly. (LLVMFuzzerMutate is the default mutator.)
    return LLVMFuzzerMutate(Data, Size, MaxSize);
  }
  PyObject* py_args = PyTuple_New(4);

  // Convert Data and Size to a ByteArray
  PyObject* py_value = PyByteArray_FromStringAndSize((const char*)Data, Size);
  if (!py_value) {
    Py_DECREF(py_args);
    fprintf(stderr, "Error: Failed to convert buffer.\n");
    py_fatal_error();
  }
  PyTuple_SetItem(py_args, 0, py_value);

  // Convert MaxSize to a PyLong
  py_value = PyLong_FromSize_t(MaxSize);
  if (!py_value) {
    Py_DECREF(py_args);
    fprintf(stderr, "Error: Failed to convert maximum size.\n");
    py_fatal_error();
  }
  PyTuple_SetItem(py_args, 1, py_value);

  // Convert Seed to a PyLong
  py_value = PyLong_FromUnsignedLong((unsigned long)Seed);
  if (!py_value) {
    Py_DECREF(py_args);
    fprintf(stderr, "Error: Failed to convert seed.\n");
    py_fatal_error();
  }
  PyTuple_SetItem(py_args, 2, py_value);

  PyObject* py_callback = PyCFunction_New(&LLVMFuzzerMutatePyMethodDef, NULL);
  if (!py_callback) {
    fprintf(stderr, "Failed to create native callback\n");
    py_fatal_error();
  }

  // Pass the native callback
  PyTuple_SetItem(py_args, 3, py_callback);

  py_value = PyObject_CallObject(py_functions[0], py_args);

  Py_DECREF(py_args);
  Py_DECREF(py_callback);

  if (py_value != NULL) {
    ssize_t ReturnedSize = PyByteArray_Size(py_value);
    if (ReturnedSize > MaxSize) {
      fprintf(stderr, "Warning: Python module returned buffer that exceeds "
                      "the maximum size. Returning a truncated buffer.\n");
      ReturnedSize = MaxSize;
    }
    memcpy(Data, PyByteArray_AsString(py_value), ReturnedSize);
    Py_DECREF(py_value);
    // return ReturnedSize; // Instead of returning the python custom mutator, we should also try to use the original custom mutator too (maybe).
    if (getenv("FUZZ_ONLY_CUSTOM")) { // Only fuzz with the custom mutator
      return ReturnedSize;
    }


    return LLVMFuzzerMutate(Data, ReturnedSize, MaxSize);

  } else {
    if (PyErr_Occurred())
      PyErr_Print();
    fprintf(stderr, "Error: Call failed\n");
    py_fatal_error();
  }
  return 0;
}


