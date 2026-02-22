#include <map>
#include <string>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <cerrno>
#include <cstring>

#include "inject.h"
#include "config.h"
#include "log.h"
#include "zygisk.h"

#if defined(__aarch64__)
#include "tracer/tracer_main.h"
#endif

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

static constexpr const char *MODULE_DIR  = "/data/adb/re.zyg.fri";
static constexpr const char *FALLBACK_DIR = "/data/local/tmp/re.zyg.fri";

// ---------------------------------------------------------------------------
// IPC helpers: length-prefixed strings over the companion socket
// ---------------------------------------------------------------------------

static bool write_string(int fd, const std::string &s) {
    uint32_t len = (uint32_t) s.size();
    if (write(fd, &len, sizeof(len)) != sizeof(len)) return false;
    if (len > 0 && write(fd, s.data(), len) != (ssize_t) len) return false;
    return true;
}

static bool read_string(int fd, std::string &out) {
    uint32_t len = 0;
    if (read(fd, &len, sizeof(len)) != sizeof(len)) return false;
    if (len == 0) { out.clear(); return true; }
    out.resize(len);
    return read(fd, &out[0], len) == (ssize_t) len;
}

// ---------------------------------------------------------------------------
// Companion: copy a library to a temp file inside the app's own data dir.
// The companion runs as root so it can write to /data/data/<pkg>/ and chown
// the file to the app's UID.  Files in app_data_file SELinux context are
// allowed to be mmap'd with PROT_EXEC by the owning app, unlike files in
// /data/local/tmp (shell_data_file context) which are blocked.
// Returns the temp path on success, empty string on failure.
// ---------------------------------------------------------------------------

static std::string companion_copy_to_appdir(const std::string &src_path,
                                             const std::string &app_name) {
    int src = open(src_path.c_str(), O_RDONLY | O_CLOEXEC);
    if (src < 0) {
        LOGW("[companion] cannot open %s: %s", src_path.c_str(), strerror(errno));
        return "";
    }

    // Determine the app's data dir and UID
    std::string app_dir = "/data/data/" + app_name;
    struct stat dir_st{};
    if (stat(app_dir.c_str(), &dir_st) != 0) {
        LOGW("[companion] cannot stat %s: %s", app_dir.c_str(), strerror(errno));
        close(src);
        return "";
    }
    uid_t app_uid = dir_st.st_uid;
    gid_t app_gid = dir_st.st_gid;

    // Build a unique temp path inside the app's data dir
    static int counter = 0;
    std::string tmp_path = app_dir + "/.zyg_" +
                           std::to_string(getpid()) + "_" +
                           std::to_string(counter++) + ".so";

    int dst = open(tmp_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0700);
    if (dst < 0) {
        LOGW("[companion] cannot create %s: %s", tmp_path.c_str(), strerror(errno));
        close(src);
        return "";
    }

    char buf[65536];
    ssize_t n;
    while ((n = read(src, buf, sizeof(buf))) > 0) {
        ssize_t written = 0;
        while (written < n) {
            ssize_t w = write(dst, buf + written, n - written);
            if (w < 0) {
                LOGW("[companion] write to tmpfile failed: %s", strerror(errno));
                close(src); close(dst);
                unlink(tmp_path.c_str());
                return "";
            }
            written += w;
        }
    }
    close(src);
    close(dst);

    // chown to the app so it can read+exec the file under SELinux
    chown(tmp_path.c_str(), app_uid, app_gid);
    chmod(tmp_path.c_str(), 0700);

    LOGI("[companion] copied %s -> %s (uid=%d)", src_path.c_str(), tmp_path.c_str(), app_uid);
    return tmp_path;
}

// ---------------------------------------------------------------------------
// Companion handler — runs as root
// Protocol:
//   1. recv app_name  -> send config JSON (empty string = not found)
//   2. recv lib_path  -> send tmp_path (empty string = error)
//      repeat until lib_path == "" (sentinel)
// ---------------------------------------------------------------------------

static void companion_handler(int client) {
    // Step 1: config JSON
    std::string app_name;
    if (!read_string(client, app_name) || app_name.empty()) {
        LOGW("[companion] failed to read app_name");
        write_string(client, "");
        return;
    }

    std::string config_path = std::string(MODULE_DIR) + "/config.json";
    std::ifstream f(config_path);
    if (!f.is_open()) {
        config_path = std::string(FALLBACK_DIR) + "/config.json";
        f.open(config_path);
    }

    if (!f.is_open()) {
        LOGW("[companion] config.json not found");
        write_string(client, "");
        return;
    }

    std::ostringstream ss;
    ss << f.rdbuf();
    std::string json = ss.str();

    // Only proceed if this app is actually a configured target.
    // This avoids sending config + libs to every app that zygote spawns.
    if (!parse_advanced_config(json, app_name).has_value()) {
        write_string(client, "");
        return;
    }

    LOGI("[companion] sending config (%zu bytes) for %s", json.size(), app_name.c_str());
    if (!write_string(client, json)) return;

    // Step 2: serve lib copy requests until empty sentinel
    while (true) {
        std::string lib_path;
        if (!read_string(client, lib_path)) break;
        if (lib_path.empty()) break;  // sentinel

        LOGI("[companion] copying lib for %s: %s", app_name.c_str(), lib_path.c_str());
        std::string tmp_path = companion_copy_to_appdir(lib_path, app_name);
        write_string(client, tmp_path);  // empty on failure
    }

    // Step 3: tracer launch request (arm64 only)
    // Protocol: recv tracer_mode string
    //   if "probe" -> recv target_pid (uint32), recv log_path -> launch tracer
    //   otherwise  -> no-op
#if defined(__aarch64__)
    std::string tracer_mode;
    if (read_string(client, tracer_mode) && tracer_mode == "probe") {
        uint32_t target_pid = 0;
        if (read(client, &target_pid, sizeof(target_pid)) == sizeof(target_pid)) {
            std::string log_path;
            read_string(client, log_path);
            LOGI("[companion] launching tracer for pid %u, log=%s",
                 target_pid, log_path.c_str());
            launch_tracer((pid_t)target_pid, log_path);
        }
    }
#endif

}

REGISTER_ZYGISK_COMPANION(companion_handler)

// ---------------------------------------------------------------------------
// Zygisk module
// ---------------------------------------------------------------------------

class MyModule : public zygisk::ModuleBase {
 public:
    void onLoad(Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        const char *raw = env->GetStringUTFChars(args->nice_name, nullptr);
        app_name = std::string(raw);
        env->ReleaseStringUTFChars(args->nice_name, raw);

        int sock = api->connectCompanion();
        if (sock < 0) {
            LOGW("[module] connectCompanion failed");
            return;
        }

        // Step 1: send app_name, receive JSON
        if (!write_string(sock, app_name)) {
            LOGW("[module] failed to send app_name");
            close(sock);
            return;
        }

        std::string json;
        if (!read_string(sock, json) || json.empty()) {
            close(sock);
            return;
        }
        companion_json = json;
        LOGI("[module] received config (%zu bytes)", json.size());

        // Step 2: parse config to know which libs to prefetch
        auto cfg = parse_advanced_config(companion_json, app_name);
        if (!cfg.has_value()) {
            write_string(sock, "");  // send sentinel
            close(sock);
            return;
        }

        // Request tmp file for each injected library
        for (auto &lib_path : cfg->injected_libraries) {
            if (!write_string(sock, lib_path)) break;

            std::string tmp_path;
            if (!read_string(sock, tmp_path) || tmp_path.empty()) {
                LOGW("[module] companion failed to copy %s", lib_path.c_str());
                continue;
            }

            LOGI("[module] tmp file ready: %s -> %s", lib_path.c_str(), tmp_path.c_str());
            tmpfile_paths[lib_path] = tmp_path;
        }

        // Send empty sentinel to end lib copy session
        write_string(sock, "");

        // Step 3: request tracer launch if configured (arm64 only)
        // The companion (root) will fork a tracer process that attaches
        // to our pid via ptrace. We send the request here in preAppSpecialize
        // because connectCompanion is only available at this stage.
#if defined(__aarch64__)
        if (cfg->tracer_mode == "probe") {
            write_string(sock, "probe");
            uint32_t my_pid = (uint32_t)getpid();
            ::write(sock, &my_pid, sizeof(my_pid));
            write_string(sock, cfg->tracer_log_path);
        } else {
            write_string(sock, "off");
        }
#else
        write_string(sock, "off");
#endif

        close(sock);
    }

    void postAppSpecialize(const AppSpecializeArgs *args) override {
        if (app_name.empty()) {
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        std::optional<target_config> cfg;

        if (!companion_json.empty()) {
            cfg = parse_advanced_config(companion_json, app_name);
        }
        if (!cfg.has_value()) {
            cfg = load_config(FALLBACK_DIR, app_name);
        }
        if (!cfg.has_value()) {
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        LOGI("App detected: %s", app_name.c_str());

        if (!cfg->enabled) {
            LOGI("Injection disabled for %s", app_name.c_str());
            // Clean up any temp files
            for (auto &kv : tmpfile_paths) unlink(kv.second.c_str());
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        // Replace lib paths with tmp file paths where available
        for (auto &lib_path : cfg->injected_libraries) {
            auto it = tmpfile_paths.find(lib_path);
            if (it != tmpfile_paths.end()) {
                LOGI("[module] using tmp path %s for %s",
                     it->second.c_str(), lib_path.c_str());
                lib_path = it->second;
            }
        }

        // Write a .config.so next to each gadget tmp file so Frida picks up
        // custom listen port / on_load behaviour.  The file must exist before
        // dlopen, and we are already running as the app UID so we can write
        // into our own data dir.
        for (auto &lib_path : cfg->injected_libraries) {
            if (lib_path.find("/.zyg_") == std::string::npos) continue;
            // <name>.so  ->  <name>.config.so
            std::string cfg_path = lib_path.substr(0, lib_path.size() - 3) + ".config.so";

            // Build Frida gadget config JSON based on interaction type
            std::string json;
            if (cfg->gadget_interaction == "connect") {
                json = "{\"interaction\":{\"type\":\"connect\"";
                json += ",\"address\":\"" + cfg->gadget_connect_address + "\"";
                json += ",\"port\":" + std::to_string(cfg->gadget_connect_port);
                json += ",\"on_load\":\"" + cfg->gadget_on_load + "\"";
                json += "}}";
            } else {
                json = "{\"interaction\":{\"type\":\"listen\"";
                if (cfg->gadget_listen_port > 0) {
                    json += ",\"address\":\"127.0.0.1\"";
                    json += ",\"port\":" + std::to_string(cfg->gadget_listen_port);
                }
                json += ",\"on_load\":\"" + cfg->gadget_on_load + "\"";
                json += "}}";
            }

            int fd = open(cfg_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
            if (fd >= 0) {
                write(fd, json.data(), json.size());
                close(fd);
                LOGI("[module] wrote gadget config %s: %s", cfg_path.c_str(), json.c_str());
            } else {
                LOGW("[module] failed to write gadget config %s: %s",
                     cfg_path.c_str(), strerror(errno));
            }
        }

        check_and_inject_with_config(cfg.value());

        // tmp files are unlinked by inject_lib() after dlopen completes.
    }

 private:
    Api *api;
    JNIEnv *env;
    std::string app_name;
    std::string companion_json;
    // original lib_path -> tmp file path in app's data dir
    std::map<std::string, std::string> tmpfile_paths;
};

REGISTER_ZYGISK_MODULE(MyModule)
