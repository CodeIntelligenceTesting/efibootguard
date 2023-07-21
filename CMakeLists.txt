cmake_minimum_required(VERSION 3.16)
project(efibootguard)

find_package(cifuzz)
enable_fuzz_testing()

set(CMAKE_CXX_STANDARD 11)
add_compile_options(-O0 -g -fno-sanitize=undefined)
add_link_options(-fuse-ld=lld)

add_library(sut STATIC
    mocks/src/wrappers.cpp
    mocks/src/mocks.c
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
    tools/bg_printenv.c
    fuzztests/lib.cpp
)

target_include_directories(sut PUBLIC
    mocks/include
    tools
    include
    .cifuzz-build/libfuzzer/address+undefined/base_c/include
)

add_fuzz_test(fuzztest "fuzztests/fuzztest.cpp")

target_link_libraries(fuzztest PRIVATE sut "-Wl,--wrap=ped_device_probe_all,--wrap=mount_partition,--wrap=unmount_partition,--wrap=open_config_file,--wrap=ped_device_get_next")