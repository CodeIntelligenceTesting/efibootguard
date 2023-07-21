
#include <fuzzer/FuzzedDataProvider.h>
#include <cifuzz/cifuzz.h>
#include <iostream>

extern "C" {
    #include "ebgenv.h"
    #include "config.h"
    #include "envdata.h"
    #include "ebgpart.h"
    #include "env_api.h"
    #include "bg_printenv.h"
}

extern void set_data_provider(void *fuzzed_data_provider);
extern void free_devices(int number);
extern void generate_devices(int number, FuzzedDataProvider *fuzzed_data);
extern PedDevice *devices;

#define BUFFER_LENGTH 256

FUZZ_TEST_SETUP() {}

FUZZ_TEST(const uint8_t *data, size_t size) {

    // Ensure a minimum data length
    if (size < 100) return;

    FuzzedDataProvider fuzzed_data(data, size);
    set_data_provider(&fuzzed_data);

    int number = fuzzed_data.ConsumeIntegralInRange<int>(1, 15);
    generate_devices(number, &fuzzed_data);

    BG_ENVDATA envdata[ENV_NUM_CONFIG_PARTS] = {0};
    CONFIG_PART config_parts[ENV_NUM_CONFIG_PARTS] = {0};

    ebgenv_t e = {0};
	memset(&e, 0, sizeof(e));
	memset(envdata, 0, sizeof(envdata));

    uint8_t ex = 0;
    uint64_t user_type = 0;

    char c_buffer[BUFFER_LENGTH] = {0};
    uint8_t uint_buffer[BUFFER_LENGTH] = {0};

    bool env_finalized = false;
    
    ebg_env_create_new(&e);

    for (int i = 0; i < fuzzed_data.ConsumeIntegralInRange(1, 20); i++) {
        int func_id = fuzzed_data.ConsumeIntegralInRange<int>(0, 9);
        func_id = 0;
        switch (func_id) {
            case 0:
                ebg_env_set(
                    &e,
                    fuzzed_data.ConsumeBytesWithTerminator<char>(fuzzed_data.ConsumeIntegralInRange<int>(10, 500)).data(),
                    fuzzed_data.ConsumeBytesWithTerminator<char>(fuzzed_data.ConsumeIntegralInRange<int>(10, 500)).data()
                );
                break;
            case 1:
                user_type = fuzzed_data.ConsumeIntegral<uint64_t>();
                break;
            case 2:
                ebg_env_get(
                    &e,
                    fuzzed_data.ConsumeBytesWithTerminator<char>(fuzzed_data.ConsumeIntegralInRange<int>(0, 500)).data(),
                    fuzzed_data.ConsumeBool() ? c_buffer : NULL
                );
                break;
            case 3:
                ebg_env_setglobalstate(
                    &e,
                    fuzzed_data.ConsumeIntegral<uint16_t>()
                );
                break;
            case 4:
                ebg_env_getglobalstate(&e);
                break;
            case 5:
                ebg_env_user_free(&e);
                break;
            case 6:
                ebg_env_set_ex(
                    &e,
                    fuzzed_data.ConsumeBytesWithTerminator<char>(fuzzed_data.ConsumeIntegralInRange<int>(0, 1000)).data(),
                    fuzzed_data.ConsumeIntegral<uint64_t>(),
                    &ex,
                    fuzzed_data.ConsumeIntegralInRange<uint32_t>(0, 1)
                );
                break;
            case 7:
                ebg_env_get_ex(
                    &e,
                    fuzzed_data.ConsumeBytesWithTerminator<char>(fuzzed_data.ConsumeIntegralInRange<int>(0, 500)).data(),
                    &user_type,
                    fuzzed_data.ConsumeBool() ? uint_buffer : NULL,
                    BUFFER_LENGTH
                );
                break;
            case 8:
                if (env_finalized) {
                    break;
                }
                ebg_env_register_gc_var(
                    &e,
                    fuzzed_data.ConsumeBytesWithTerminator<char>(fuzzed_data.ConsumeIntegralInRange<int>(0, 500)).data()
                );
                break;
            case 9:
                if (!env_finalized) {
                    ebg_env_finalize_update(&e);
                    env_finalized = true;
                }
                break;
        }
    }

    // Close env
    if (!env_finalized) {
        ebg_env_finalize_update(&e);
    }

    ebg_env_close(&e);

    free_devices(number);
}
