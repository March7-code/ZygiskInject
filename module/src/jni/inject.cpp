#include "inject.h"

#include <dlfcn.h>
#include <unistd.h>

#include <string>

#include "config.h"
#include "log.h"
#include "inject_stealth.h"
#include "runtime/injector.h"
#include "xdl.h"

void inject_lib(std::string const &lib_path, std::string const &logContext) {
    bool is_tmp = lib_path.find("/.zyg_") != std::string::npos;

    auto cleanup_tmp = [&]() {
        if (!is_tmp) return;
        unlink(lib_path.c_str());
        std::string cfg_path = lib_path.substr(0, lib_path.size() - 3) + ".config.so";
        unlink(cfg_path.c_str());
    };

    auto *handle = xdl_open(lib_path.c_str(), XDL_TRY_FORCE_LOAD);
    if (handle) {
        LOGI("%sInjected %s with handle %p", logContext.c_str(), lib_path.c_str(), handle);
        cleanup_tmp();

        xdl_info_t info{};
        void *cache = nullptr;
        uintptr_t load_base = 0;
        if (xdl_info(handle, XDL_DI_DLINFO, &info) == 0 && info.dli_fbase) {
            load_base = (uintptr_t)info.dli_fbase;
        }
        inject_stealth::post_library_load_hide(load_base, lib_path, logContext);
        xdl_addr_clean(&cache);
        return;
    }

    auto xdl_err = dlerror();

    void *dl_handle = dlopen(lib_path.c_str(), RTLD_NOW);
    if (dl_handle) {
        LOGI("%sInjected %s with handle %p (dlopen)", logContext.c_str(), lib_path.c_str(), dl_handle);
        cleanup_tmp();

        Dl_info dl_info{};
        uintptr_t load_base = 0;
        if (dladdr(dl_handle, &dl_info) && dl_info.dli_fbase) {
            load_base = (uintptr_t)dl_info.dli_fbase;
        }
        inject_stealth::post_library_load_hide(load_base, lib_path, logContext);
        return;
    }

    cleanup_tmp();
    auto dl_err = dlerror();
    LOGE("%sFailed to inject %s (xdl_open): %s", logContext.c_str(), lib_path.c_str(), xdl_err);
    LOGE("%sFailed to inject %s (dlopen): %s", logContext.c_str(), lib_path.c_str(), dl_err);
}

bool check_and_inject(std::string const &app_name) {
    std::string module_dir = std::string("/data/adb/re.zyg.fri");

    std::optional<target_config> cfg = load_config(module_dir, app_name);
    if (!cfg.has_value()) {
        return false;
    }

    LOGI("App detected: %s", app_name.c_str());
    LOGI("PID: %d", getpid());


    auto target_config = cfg.value();
    if (!target_config.enabled) {
        LOGI("Injection disabled for %s", app_name.c_str());
        return false;
    }

    runtime::start_injection(target_config);

    return true;
}

void check_and_inject_with_config(target_config const &cfg) {
    LOGI("PID: %d", getpid());
    runtime::start_injection(cfg);
}
