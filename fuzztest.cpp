
#include <fuzzer/FuzzedDataProvider.h>
#include <cifuzz/cifuzz.h>
#include <thread>
#include <sys/wait.h>
#include <iostream>

extern "C" {
    #include "ebgenv.h"
    #include "config.h"
    #include "envdata.h"
}


#define BUFFER_LENGTH 256


static void toCharArray(const uint8_t* bytes, size_t size, char* charArray) {
    for (size_t i = 0; i < size; ++i) {
        charArray[i] = static_cast<char>(bytes[i]);
    }
}

FUZZ_TEST(const uint8_t *data, size_t size) {
    FuzzedDataProvider fuzzed_data(data, size);

    BG_ENVDATA envdata[8];

    ebgenv_t e;
	uint16_t state;
	memset(&e, 0, sizeof(e));
	memset(envdata, 0, sizeof(envdata));

    char* key;
    char* value;

    uint8_t ex;
    uint64_t user_type;

    char c_buffer[BUFFER_LENGTH] = {0};
    uint8_t uint_buffer[BUFFER_LENGTH] = {0};

    for (int i = 0; i < fuzzed_data.ConsumeIntegralInRange(0, 50); i++) {
        int func_id = fuzzed_data.ConsumeIntegralInRange<int>(0, 12);
        switch (func_id) {
            case 0:
                ebg_env_set(&e, key, value);
                break;
            case 1:
                ebg_env_open_current(&e);
                break;
            case 2:
                ebg_env_get(&e, key, c_buffer);
                break;
            case 3:
            	ebg_env_create_new(&e);
                break;
            case 4:
                key = fuzzed_data.ConsumeBytesWithTerminator<char>(fuzzed_data.ConsumeIntegral<size_t>()).data();
                value = fuzzed_data.ConsumeBytesWithTerminator<char>(fuzzed_data.ConsumeIntegral<size_t>()).data();
                break;
            case 5:
                ebg_env_close(&e);
                break;
            case 6:
                ebg_env_setglobalstate(&e, fuzzed_data.ConsumeIntegral<uint16_t>());
                break;
            case 7:
                ebg_env_finalize_update(&e);
                break;
            case 8:
                ebg_env_getglobalstate(&e);
                break;
            case 9:
                ebg_env_user_free(&e);
                break;
            case 10:
                ebg_env_set_ex(&e, key, fuzzed_data.ConsumeIntegral<uint64_t>(), &ex, fuzzed_data.ConsumeIntegral<uint32_t>());
                break;
            case 11:
                ebg_env_get_ex(&e, key, &user_type, uint_buffer, BUFFER_LENGTH);
                break;
            case 12:
                ebg_env_register_gc_var(&e, key);
                break;
        }
    }

}
