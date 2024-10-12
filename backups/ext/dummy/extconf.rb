# frozen_string_literal: true

require 'mkmf'

CC = ENV.fetch('CC', 'clang')
CXX = ENV.fetch('CXX', 'clang++')
AR = ENV.fetch('AR', 'ar')
FUZZER_NO_MAIN_LIB_ENV = 'FUZZER_NO_MAIN_LIB'

find_executable(CC)
find_executable(CXX)

# https://github.com/google/sanitizers/wiki/AddressSanitizerFlags
$CFLAGS = '-fsanitize=address,fuzzer-no-link -fno-omit-frame-pointer -fno-common -fPIC -g'
$CXXFLAGS = '-fsanitize=address,fuzzer-no-link -fno-omit-frame-pointer -fno-common -fPIC -g'

create_makefile('dummy/dummy')
