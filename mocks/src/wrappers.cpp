
#include <fuzzer/FuzzedDataProvider.h>

static FuzzedDataProvider *fuzzed_data;

void set_data_provider(void *fuzzed_data_provider) {
    fuzzed_data = (FuzzedDataProvider *) fuzzed_data_provider;
}

extern "C" {
    #include "ebgpart.h"
    #include "env_api.h"
}

extern PedDevice *devices;
extern std::vector<std::string> strings;

extern "C" {
    PedDevice *__wrap_ped_device_get_next(const PedDevice *dev) {
        if (!dev) {
            return devices;
        }

    	return dev->next;
    }

    void __wrap_ped_device_probe_all() {}

    bool __wrap_mount_partition(CONFIG_PART *cfgpart) {
        // Trigger memory leak
        // if (fuzzed_data->ConsumeBool()) {
        //     return false;
        // }

        std::string mountpoint_str = fuzzed_data->ConsumeBytesAsString(10);
        char *mountpoint = &mountpoint_str[0];
        cfgpart->mountpoint = (char *)malloc(strlen(mountpoint) + 1);
        strcpy(cfgpart->mountpoint, mountpoint);
        return true;
    }

    void __wrap_unmount_partition(CONFIG_PART *cfgpart)
    {
        if (!cfgpart) {
            return;
        }
        if (!cfgpart->mountpoint) {
            return;
        }
        free(cfgpart->mountpoint);
        cfgpart->mountpoint = NULL;
    }

    FILE *__wrap_open_config_file(char *configfilepath, char *mode) {
        // Trigger memory leak
        // if (fuzzed_data->ConsumeBool()) {
        //     return NULL;
        // }

        FILE *file = tmpfile();
        std::string data = fuzzed_data->ConsumeBytesAsString( fuzzed_data->ConsumeIntegralInRange<size_t>(0, 1000));
        fwrite(data.c_str(), sizeof(char), data.size(), file);
        rewind(file);
        return file;
    }
}
