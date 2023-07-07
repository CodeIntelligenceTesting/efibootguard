cmake_minimum_required(VERSION 3.16)
project(efibootguard)

find_package(cifuzz)
enable_fuzz_testing()

set(CMAKE_CXX_STANDARD 11)
add_compile_options(-O0 -g)

add_fuzz_test(fuzztest "fuzztest.cpp")

add_library(sut STATIC
    stubs/src/mocks.c
    tools/bg_setenv.c
    tools/bg_envtools.c
    env/env_api.c
    env/env_api_fat.c
    tools/bg_printenv.c
    env/env_config_file.c
    env/uservars.c
    tools/ebgpart.c
    env/env_disk_utils.c
    env/env_config_partitions.c
)

target_include_directories(sut PUBLIC
    stubs/include
    tools
    include
    .cifuzz-build/libfuzzer/address+undefined/base_c/include
)

target_link_libraries(fuzztest PRIVATE sut)