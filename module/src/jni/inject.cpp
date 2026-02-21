#include "inject.h"

#include <dobby.h>
#include <pthread.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cinttypes>
#include <filesystem>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <utility>

#include "config.h"
#include "log.h"
#include "child_gating.h"
#include "xdl.h"
#include "remapper.h"
#include "solist_patch.h"

static std::string get_process_name() {
    auto path = "/proc/self/cmdline";

    std::ifstream file(path);
    std::stringstream buffer;

    buffer << file.rdbuf();
    return buffer.str();
}

static void wait_for_init(std::string const &app_name) {
    LOGI("Wait for process to complete init");

    // wait until the process is renamed to the package name
    while (get_process_name().find(app_name) == std::string::npos) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // additional tolerance for the init to complete after process rename
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    LOGI("Process init completed");
}

static void delay_start_up(uint64_t start_up_delay_ms) {
    if (start_up_delay_ms <= 0) {
        return;
    }

    LOGI("Waiting for configured start up delay %" PRIu64"ms", start_up_delay_ms);

    int countdown = 0;
    uint64_t delay = start_up_delay_ms;

    for (int i = 0; i < 10 && delay > 1000; i++) {
        delay -= 1000;
        countdown++;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    for (int i = countdown; i > 0; i--) {
        LOGI("Injecting libs in %d seconds", i);
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

// Thread names created by frida-gadget on Android/Linux (verified from source):
//   gadget-glue.c:111        -> "frida-gadget"    (gadget worker loop)
//   frida-glue.c:47          -> "frida-main-loop"  (frida-core main loop)
//   gumscriptscheduler.c:117 -> "gum-js-loop"      (JS engine thread)
// Matched as prefix so "frida-gadget" also catches any future "frida-gadget-N".
//
// GLib internals ("gmain", "gdbus") are intentionally excluded to avoid
// accidentally renaming threads from apps that use GLib themselves.
static const char *const FRIDA_THREAD_NAMES[] = {
    "frida-gadget",
    "frida-main-loop",
    "gum-js-loop",
    // "gmain",   // excluded: may collide with app's own GLib threads
    // "gdbus",   // excluded: may collide with app's own GLib threads
    nullptr
};

// Replacement name used for all matched threads. Must be <= 15 chars.
// Defaults to "pool-1-thread-1"; overridden per-target via config.
static std::string g_thread_disguise_name = "pool-1-thread-1";

static bool is_frida_thread_name(const char *name) {
    for (int i = 0; FRIDA_THREAD_NAMES[i] != nullptr; i++) {
        if (strncmp(name, FRIDA_THREAD_NAMES[i], strlen(FRIDA_THREAD_NAMES[i])) == 0) {
            return true;
        }
    }
    return false;
}

// Hook state for pthread_setname_np interception.
// The hook is installed just before dlopen and removed once all frida threads
// have been renamed (tracked by a counter that decrements to zero).
static int (*orig_pthread_setname_np)(pthread_t, const char *) = nullptr;

// Number of frida thread names we still expect to see.  When it reaches 0 the
// hook removes itself.  Initialised to the number of non-null entries in
// FRIDA_THREAD_NAMES each time install_thread_rename_hook() is called.
static std::atomic<int> g_remaining_renames{0};

static int my_pthread_setname_np(pthread_t thread, const char *name) {
    if (name && is_frida_thread_name(name)) {
        const char *disguise = g_thread_disguise_name.c_str();
        LOGI("[thread_rename] intercepted '%s' -> '%s'", name, disguise);
        int ret = orig_pthread_setname_np(thread, disguise);

        // Unhook once all expected frida threads have been renamed.
        if (--g_remaining_renames <= 0) {
            DobbyDestroy(reinterpret_cast<void *>(orig_pthread_setname_np));
            orig_pthread_setname_np = nullptr;
            LOGI("[thread_rename] all frida threads renamed, hook removed");
        }
        return ret;
    }
    return orig_pthread_setname_np(thread, name);
}

static void install_thread_rename_hook() {
    // Count how many thread names we expect to intercept.
    int count = 0;
    for (int i = 0; FRIDA_THREAD_NAMES[i] != nullptr; i++) count++;
    g_remaining_renames.store(count);

    void *sym = dlsym(RTLD_DEFAULT, "pthread_setname_np");
    if (!sym) {
        LOGW("[thread_rename] pthread_setname_np not found, skipping hook");
        return;
    }

    int rc = DobbyHook(sym,
                       reinterpret_cast<void *>(my_pthread_setname_np),
                       reinterpret_cast<void **>(&orig_pthread_setname_np));
    if (rc != 0) {
        LOGW("[thread_rename] DobbyHook failed (%d), skipping", rc);
        orig_pthread_setname_np = nullptr;
    } else {
        LOGI("[thread_rename] pthread_setname_np hook installed");
    }
}

void inject_lib(std::string const &lib_path, std::string const &logContext) {
    // Install the pthread_setname_np hook before dlopen so we intercept frida's
    // thread names at the exact moment they are set, with no polling window.
    install_thread_rename_hook();

    auto *handle = xdl_open(lib_path.c_str(), XDL_TRY_FORCE_LOAD);
    if (handle) {
        LOGI("%sInjected %s with handle %p", logContext.c_str(), lib_path.c_str(), handle);
        remap_lib(lib_path);
        xdl_info_t info{};
        void *cache = nullptr;
        if (xdl_info(handle, XDL_DI_DLINFO, &info) == 0 && info.dli_fbase) {
            solist_remove_lib((uintptr_t)info.dli_fbase);
        } else {
            LOGW("%sFailed to get load address for solist removal: %s", logContext.c_str(), lib_path.c_str());
        }
        xdl_addr_clean(&cache);
        return;
    }

    auto xdl_err = dlerror();

    handle = dlopen(lib_path.c_str(), RTLD_NOW);
    if (handle) {
        LOGI("%sInjected %s with handle %p (dlopen)", logContext.c_str(), lib_path.c_str(), handle);
        remap_lib(lib_path);
        Dl_info dl_info{};
        if (dladdr(handle, &dl_info) && dl_info.dli_fbase) {
            solist_remove_lib((uintptr_t)dl_info.dli_fbase);
        } else {
            LOGW("%sFailed to get load address for solist removal: %s", logContext.c_str(), lib_path.c_str());
        }
        return;
    }

    // Both injection methods failed; remove the hook we installed.
    if (orig_pthread_setname_np) {
        DobbyDestroy(reinterpret_cast<void *>(orig_pthread_setname_np));
        orig_pthread_setname_np = nullptr;
    }

    auto dl_err = dlerror();
    LOGE("%sFailed to inject %s (xdl_open): %s", logContext.c_str(), lib_path.c_str(), xdl_err);
    LOGE("%sFailed to inject %s (dlopen): %s", logContext.c_str(), lib_path.c_str(), dl_err);
}

static void inject_libs(target_config const &cfg) {
    wait_for_init(cfg.app_name);

    if (cfg.child_gating.enabled) {
        enable_child_gating(cfg.child_gating);
    }

    delay_start_up(cfg.start_up_delay_ms);

    // Apply per-target thread disguise name if configured.
    if (!cfg.thread_disguise_name.empty()) {
        g_thread_disguise_name = cfg.thread_disguise_name;
        LOGI("Thread disguise name set to '%s'", g_thread_disguise_name.c_str());
    }

    for (auto &lib_path : cfg.injected_libraries) {
        LOGI("Injecting %s", lib_path.c_str());
        inject_lib(lib_path, "");
    }
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

    std::thread inject_thread(inject_libs, target_config);
    inject_thread.detach();

    return true;
}

void check_and_inject_with_config(target_config const &cfg) {
    LOGI("PID: %d", getpid());
    std::thread inject_thread(inject_libs, cfg);
    inject_thread.detach();
}
