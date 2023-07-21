#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>

extern "C" {
    #include "ebgenv.h"
    #include "config.h"
    #include "envdata.h"
    #include "ebgpart.h"
    #include "env_api.h"
    #include "bg_printenv.h"
}

PedDevice *devices;

void generate_devices(int number, FuzzedDataProvider *fuzzed_data) {
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

void free_devices(int number) {
    if (!devices) {
        return;
    }

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