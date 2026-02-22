#include "inject.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <chrono>
#include <cinttypes>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "config.h"
#include "log.h"
#include "child_gating.h"
#include "xdl.h"
#include "remapper.h"
#include "solist_patch.h"

#if defined(__aarch64__)
#include "tracer/tracer_main.h"
#endif

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

// ---------------------------------------------------------------------------
// /proc/net/tcp filtering — hide frida gadget's outgoing connection
// ---------------------------------------------------------------------------
// When gadget uses connect mode, the ESTABLISHED connection shows up in
// /proc/net/tcp (or tcp6).  Detection code reads these files to find
// suspicious ports.  We hook open/openat to return a filtered fd.

static std::vector<uint16_t> g_hide_ports;  // host byte order ports to hide

static int (*real_open)(const char *, int, ...) = nullptr;
static int (*real_openat)(int, const char *, int, ...) = nullptr;

// Check if a path is /proc/net/tcp or /proc/net/tcp6
static bool is_proc_net_tcp(const char *path) {
    if (!path) return false;
    return strcmp(path, "/proc/net/tcp") == 0 ||
           strcmp(path, "/proc/net/tcp6") == 0 ||
           strcmp(path, "/proc/self/net/tcp") == 0 ||
           strcmp(path, "/proc/self/net/tcp6") == 0;
}

// Build a filtered copy of /proc/net/tcp that omits lines containing any
// hidden port.  Ports appear as hex in columns 2 (local) and 3 (remote).
static int make_filtered_tcp_fd(const char *real_path) {
    // Read the real file via raw syscall to bypass our own hook
    int src = syscall(__NR_openat, AT_FDCWD, real_path, O_RDONLY | O_CLOEXEC);
    if (src < 0) return -1;

    std::string content;
    char buf[4096];
    ssize_t n;
    while ((n = read(src, buf, sizeof(buf))) > 0) {
        content.append(buf, n);
    }
    close(src);

    // Build hex needles for all hidden ports
    std::vector<std::string> needles;
    for (uint16_t port : g_hide_ports) {
        char hex[8];
        snprintf(hex, sizeof(hex), ":%04X", port);
        needles.emplace_back(hex);
    }

    // Filter line by line
    std::string filtered;
    std::istringstream stream(content);
    std::string line;
    bool first_line = true;
    while (std::getline(stream, line)) {
        if (first_line) {
            filtered += line + "\n";
            first_line = false;
            continue;
        }
        bool hide = false;
        for (auto &needle : needles) {
            if (line.find(needle) != std::string::npos) {
                hide = true;
                break;
            }
        }
        if (hide) continue;
        filtered += line + "\n";
    }

    // Create an in-memory fd via memfd_create (API 26+) or a pipe
    int memfd = syscall(__NR_memfd_create, "tcp", 0);
    if (memfd < 0) {
        int pipefd[2];
        if (pipe(pipefd) < 0) return -1;
        write(pipefd[1], filtered.data(), filtered.size());
        close(pipefd[1]);
        return pipefd[0];
    }

    write(memfd, filtered.data(), filtered.size());
    lseek(memfd, 0, SEEK_SET);
    return memfd;
}

static int hook_openat(int dirfd, const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, int);
        va_end(ap);
    }

    if (!g_hide_ports.empty() && is_proc_net_tcp(pathname)) {
        int fd = make_filtered_tcp_fd(pathname);
        if (fd >= 0) return fd;
    }

    return real_openat(dirfd, pathname, flags, mode);
}

static int hook_open(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, int);
        va_end(ap);
    }

    if (!g_hide_ports.empty() && is_proc_net_tcp(pathname)) {
        int fd = make_filtered_tcp_fd(pathname);
        if (fd >= 0) return fd;
    }

    return real_open(pathname, flags, mode);
}

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
        if (xdl_info(handle, XDL_DI_DLINFO, &info) == 0 && info.dli_fbase) {
            solist_remove_lib((uintptr_t)info.dli_fbase);
        } else {
            LOGW("%sFailed to get load address: %s", logContext.c_str(), lib_path.c_str());
        }
        xdl_addr_clean(&cache);

        remap_lib(lib_path);
        return;
    }

    auto xdl_err = dlerror();

    void *dl_handle = dlopen(lib_path.c_str(), RTLD_NOW);
    if (dl_handle) {
        LOGI("%sInjected %s with handle %p (dlopen)", logContext.c_str(), lib_path.c_str(), dl_handle);
        cleanup_tmp();

        Dl_info dl_info{};
        if (dladdr(dl_handle, &dl_info) && dl_info.dli_fbase) {
            solist_remove_lib((uintptr_t)dl_info.dli_fbase);
        } else {
            LOGW("%sFailed to get load address: %s", logContext.c_str(), lib_path.c_str());
        }

        remap_lib(lib_path);
        return;
    }

    cleanup_tmp();
    auto dl_err = dlerror();
    LOGE("%sFailed to inject %s (xdl_open): %s", logContext.c_str(), lib_path.c_str(), xdl_err);
    LOGE("%sFailed to inject %s (dlopen): %s", logContext.c_str(), lib_path.c_str(), dl_err);
}

static void inject_libs(target_config const &cfg) {
    // Set up /proc/net/tcp filtering — auto-derive port from interaction mode.
    if (cfg.gadget_interaction == "connect" && cfg.gadget_connect_port > 0) {
        g_hide_ports.push_back(cfg.gadget_connect_port);
    } else {
        // listen mode: hide the listen port (default 27042)
        uint16_t lport = cfg.gadget_listen_port > 0 ? cfg.gadget_listen_port : 27042;
        g_hide_ports.push_back(lport);
    }
    LOGI("[net_filter] hiding port %d from /proc/net/tcp", g_hide_ports[0]);

    wait_for_init(cfg.app_name);

    if (cfg.child_gating.enabled) {
        enable_child_gating(cfg.child_gating);
    }

    delay_start_up(cfg.start_up_delay_ms);

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
