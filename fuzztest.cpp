
#include <fuzzer/FuzzedDataProvider.h>
#include <cifuzz/cifuzz.h>
#include <iostream>

extern "C" {
    #include "ebgenv.h"
    #include "config.h"
    #include "envdata.h"
    #include "ebgpart.h"
    #include "env_api.h"
}

PedDevice *devices;
std::vector<std::string> strings;

extern void set_data_provider(void *fuzzed_data_provider);

#define BUFFER_LENGTH 256

void static generate_devices(int number, FuzzedDataProvider *fuzzed_data) {
    // Create some random devices
    devices = (PedDevice *)calloc(number, sizeof(PedDevice));

    for (int i = 0; i < number; i++) {
        std::string model_str = fuzzed_data->ConsumeBytesAsString(fuzzed_data->ConsumeIntegralInRange<size_t>(5, 50));
        char *model = (char *) malloc(model_str.size() + 1);
        strcpy(model, model_str.c_str());

        std::string path_str = fuzzed_data->ConsumeBytesAsString(fuzzed_data->ConsumeIntegralInRange<size_t>(5, 50));
        char *path = (char *) malloc(path_str.size() + 1);
        strcpy(path, path_str.c_str());

        devices[i].path = path;
        devices[i].model = model;
    }

    for (int i = number - 1; i > 0; i--) {
        devices[i - 1].next = &devices[i];
    }

	for (int i = 0; i < ENV_NUM_CONFIG_PARTS; i++) {
        PedPartition **pp = &devices[0].part_list;
        int16_t num = 0;
        while (*pp) {
            pp = &(*pp)->next;
            num++;
        }
        *pp = (PedPartition *)calloc(1, sizeof(PedPartition));
        (*pp)->num = fuzzed_data->ConsumeIntegralInRange<uint16_t>(0, 100);

        PedFileSystemType *fs_type = (PedFileSystemType *) malloc(sizeof(PedFileSystemType));

        // Trigger memory leak
        // std::string fs_name_str = fuzzed_data->ConsumeBytesAsString(fuzzed_data->ConsumeIntegralInRange<size_t>(5, 100));
        std::string fs_name_str = "fat12";
        fs_type->name = (char*)malloc(fs_name_str.size() + 1);
        strcpy(fs_type->name, fs_name_str.c_str());

        (*pp)->fs_type = fs_type;
    }
}

FUZZ_TEST_SETUP() {}

FUZZ_TEST(const uint8_t *data, size_t size) {

    // Ensure a minimum data length
    if (size < 100) return;

    FuzzedDataProvider fuzzed_data(data, size);
    set_data_provider(&fuzzed_data);

    strings.clear();
    for (int i = 0; i < fuzzed_data.ConsumeIntegralInRange<int>(10, 30); i++) {
        strings.push_back(fuzzed_data.ConsumeBytesAsString(fuzzed_data.ConsumeIntegralInRange<int>(5, 200)));
    }

    BG_ENVDATA envdata[ENV_NUM_CONFIG_PARTS] = {0};
    CONFIG_PART config_parts[ENV_NUM_CONFIG_PARTS] = {0};

    int number = fuzzed_data.ConsumeIntegralInRange<int>(1, 10);
    generate_devices(number, &fuzzed_data);

    ebgenv_t e;
	memset(&e, 0, sizeof(e));
	memset(envdata, 0, sizeof(envdata));

    uint8_t ex;
    uint64_t user_type;

    char c_buffer[BUFFER_LENGTH] = {0};
    uint8_t uint_buffer[BUFFER_LENGTH] = {0};
    std::string key_str;
    std::string value_str;

    bool env_finalized = false;
    
    ebg_env_create_new(&e);
    
    for (int i = 0; i < fuzzed_data.ConsumeIntegralInRange(0, 20); i++) {
        int func_id = fuzzed_data.ConsumeIntegralInRange<int>(0, 9);
        switch (func_id) {
            case 0:
                ebg_env_set(
                    &e,
                    &strings[fuzzed_data.ConsumeIntegralInRange<size_t>(0, strings.size() - 1)][0],
                    &strings[fuzzed_data.ConsumeIntegralInRange<size_t>(0, strings.size() - 1)][0]
                );
                break;
            case 1:
                user_type = fuzzed_data.ConsumeIntegral<uint64_t>();
                break;
            case 2:
                ebg_env_get(
                    &e,
                    &strings[fuzzed_data.ConsumeIntegralInRange<size_t>(0, strings.size() - 1)][0],
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
                    &strings[fuzzed_data.ConsumeIntegralInRange<size_t>(0, strings.size() - 1)][0],
                    fuzzed_data.ConsumeIntegral<uint64_t>(),
                    &ex,
                    fuzzed_data.ConsumeIntegralInRange<uint32_t>(0, 1)
                );
                break;
            case 7:
                ebg_env_get_ex(
                    &e,
                    &strings[fuzzed_data.ConsumeIntegralInRange<size_t>(0, strings.size() - 1)][0],
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
                    &strings[fuzzed_data.ConsumeIntegralInRange<size_t>(0, strings.size() - 1)][0]
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

    // Free dynamically allocated devices
    for (int i = 0; i < number; i++) {
        free(devices[i].model);
		free(devices[i].path);

        PedPartition *pp = devices[i].part_list;
	    PedPartition *next;
        while (pp) {
            next = pp->next;
            free(pp->fs_type->name);
            free(pp->fs_type);
            free(pp);
            pp = next;
        }
    }

    free(devices);
}
