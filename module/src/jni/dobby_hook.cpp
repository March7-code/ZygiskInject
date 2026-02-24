#include "dobby_hook.h"
#include "log.h"

#if defined(__aarch64__)

#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <string>
#include <vector>
#include <mutex>
#include <fstream>
#include "dobby.h"

static std::vector<so_hook_config> g_hook_configs;
static std::mutex g_hook_mutex;
static bool g_all_hooked = false;

static int hook_return_0() { return 0; }
static int hook_return_1() { return 1; }
static int hook_return_neg1() { return -1; }

static void *get_return_stub(int return_value) {
    switch (return_value) {
        case 0:  return (void *)hook_return_0;
        case 1:  return (void *)hook_return_1;
        case -1: return (void *)hook_return_neg1;
        default: return (void *)hook_return_0;
    }
}

static uintptr_t find_module_base(const char *so_name) {
    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open()) return 0;

    std::string line;
    while (std::getline(maps, line)) {
        if (line.find(so_name) == std::string::npos) continue;
        if (line.find("r-xp") == std::string::npos &&
            line.find("r--xp") == std::string::npos) continue;

        uintptr_t base = 0;
        if (sscanf(line.c_str(), "%" SCNxPTR, &base) == 1) {
            return base;
        }
    }
    return 0;
}

static void apply_hooks_for_so(const char *so_name) {
    std::lock_guard<std::mutex> lock(g_hook_mutex);
    if (g_all_hooked) return;

    for (auto &shc : g_hook_configs) {
        if (shc.so_name != so_name) continue;

        uintptr_t base = find_module_base(shc.so_name.c_str());
        if (base == 0) {
            LOGW("[dobby] %s loaded but base not found in maps", so_name);
            return;
        }

        LOGI("[dobby] %s loaded at base 0x%" PRIxPTR, so_name, base);

        for (auto &hp : shc.hooks) {
            void *target = (void *)(base + hp.offset);
            void *stub = get_return_stub(hp.return_value);
            int ret = DobbyHook(target, stub, nullptr);
            if (ret == 0) {
                LOGI("[dobby] hooked 0x%" PRIx64 " at %p -> return %d",
                     hp.offset, target, hp.return_value);
            } else {
                LOGW("[dobby] hook failed 0x%" PRIx64 " at %p (err=%d)",
                     hp.offset, target, ret);
            }
        }

        // Mark this SO as done; check if all SOs are hooked
        shc.hooks.clear();
        bool all_done = true;
        for (auto &s : g_hook_configs) {
            if (!s.hooks.empty()) { all_done = false; break; }
        }
        if (all_done) g_all_hooked = true;
        return;
    }
}

// Hook android_dlopen_ext to intercept SO loading
typedef void *(*android_dlopen_ext_t)(const char *, int, const void *);
static android_dlopen_ext_t orig_android_dlopen_ext = nullptr;

static void *hook_android_dlopen_ext(const char *filename, int flags,
                                      const void *extinfo) {
    void *handle = orig_android_dlopen_ext(filename, flags, extinfo);

    if (filename && handle && !g_all_hooked) {
        const char *basename = strrchr(filename, '/');
        basename = basename ? basename + 1 : filename;
        LOGI("[dobby] dlopen intercepted: %s", basename);
        apply_hooks_for_so(basename);
    }

    return handle;
}

void setup_dobby_hooks(const std::vector<so_hook_config> &hooks) {
    if (hooks.empty()) return;

    {
        std::lock_guard<std::mutex> lock(g_hook_mutex);
        g_hook_configs = hooks;
        g_all_hooked = false;
    }

    // Hook android_dlopen_ext to monitor SO loading
    void *sym = DobbySymbolResolver(nullptr, "android_dlopen_ext");
    if (!sym) {
        // Fallback: try __loader_android_dlopen_ext
        sym = DobbySymbolResolver(nullptr, "__loader_android_dlopen_ext");
    }
    if (!sym) {
        LOGW("[dobby] cannot find android_dlopen_ext symbol");
        return;
    }

    int ret = DobbyHook(sym, (void *)hook_android_dlopen_ext,
                         (void **)&orig_android_dlopen_ext);
    if (ret != 0) {
        LOGW("[dobby] failed to hook android_dlopen_ext (err=%d)", ret);
        return;
    }

    LOGI("[dobby] hooked android_dlopen_ext, watching %zu so(s)", hooks.size());
    for (auto &shc : hooks) {
        LOGI("[dobby]   watching: %s (%zu hooks)",
             shc.so_name.c_str(), shc.hooks.size());
    }
}

#else  // !__aarch64__

void setup_dobby_hooks(const std::vector<so_hook_config> & /*hooks*/) {
}

#endif
