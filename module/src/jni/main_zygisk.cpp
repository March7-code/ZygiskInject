#include <map>
#include <string>
#include <fstream>
#include <sstream>
#include <thread>
#include <vector>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#include <cstddef>
#include <cstdint>
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

static bool write_u16(int fd, uint16_t value) {
    return write(fd, &value, sizeof(value)) == sizeof(value);
}

static bool read_u16(int fd, uint16_t &value) {
    return read(fd, &value, sizeof(value)) == sizeof(value);
}

static bool write_u8(int fd, uint8_t value) {
    return write(fd, &value, sizeof(value)) == sizeof(value);
}

static bool read_u8(int fd, uint8_t &value) {
    return read(fd, &value, sizeof(value)) == sizeof(value);
}

static bool write_all(int fd, const void *buf, size_t len) {
    auto *p = static_cast<const uint8_t *>(buf);
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, p + off, len - off);
        if (n <= 0) return false;
        off += (size_t)n;
    }
    return true;
}

static int connect_tcp_endpoint(const std::string &host, uint16_t port) {
    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned int)port);

    struct addrinfo *res = nullptr;
    if (getaddrinfo(host.c_str(), port_str, &hints, &res) != 0) {
        return -1;
    }

    int fd = -1;
    for (auto *ai = res; ai != nullptr; ai = ai->ai_next) {
        int s = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
        if (s < 0) continue;
        if (connect(s, ai->ai_addr, ai->ai_addrlen) == 0) {
            fd = s;
            break;
        }
        close(s);
    }

    freeaddrinfo(res);
    return fd;
}

static std::string sanitize_socket_name(const std::string &name) {
    std::string out;
    out.reserve(name.size());
    for (char c : name) {
        bool ok = (c >= 'a' && c <= 'z') ||
                  (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') ||
                  c == '.' || c == '_' || c == '-';
        out.push_back(ok ? c : '_');
    }
    return out;
}

static bool is_numeric_service_name(const std::string &name) {
    if (name.empty() || name.size() > 5) return false;
    unsigned value = 0;
    for (char c : name) {
        if (c < '0' || c > '9') return false;
        value = value * 10u + (unsigned)(c - '0');
        if (value > 65535u) return false;
    }
    return value != 0;
}

static std::string generate_unix_socket_name(const std::string &app_name) {
    static uint32_t counter = 0;
    // NOTE:
    // frida-gadget connect-mode still runs its HTTP/WebSocket host parser on
    // the "address" field. Non-numeric abstract UNIX names (e.g. "a.b.c")
    // trigger "Unknown service ... in hostname 'unix:...'" in GLib.
    // Use a numeric abstract name (1..65535) so parsing always succeeds.
    uint32_t h = 5381u;
    for (char c : app_name) {
        h = ((h << 5u) + h) + (uint8_t) c;  // djb2
    }
    uint32_t seed = h ^ (uint32_t) getpid() ^ counter++;
    uint32_t value = 10000u + (seed % 50000u);  // 10000..59999
    return std::to_string(value);
}

static int bind_abstract_unix_listener(const std::string &name) {
    if (name.empty()) return -1;
    if (name.size() > sizeof(sockaddr_un().sun_path) - 2) return -1;

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';  // abstract namespace
    memcpy(addr.sun_path + 1, name.data(), name.size());
    socklen_t len = (socklen_t)(offsetof(sockaddr_un, sun_path) + 1 + name.size());

    if (bind(fd, reinterpret_cast<sockaddr *>(&addr), len) != 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, 1) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void run_unix_tcp_proxy_once(int listen_fd,
                                    const std::string &target_host,
                                    uint16_t target_port) {
    pollfd accept_pfd{listen_fd, POLLIN, 0};
    int pr = poll(&accept_pfd, 1, 300000);  // wait up to 5m for gadget
    if (pr <= 0) {
        close(listen_fd);
        return;
    }

    int local_fd = accept(listen_fd, nullptr, nullptr);
    close(listen_fd);
    if (local_fd < 0) return;

    int remote_fd = connect_tcp_endpoint(target_host, target_port);
    if (remote_fd < 0) {
        close(local_fd);
        return;
    }

    uint8_t buf[8192];
    pollfd fds[2] = {
            {local_fd, POLLIN, 0},
            {remote_fd, POLLIN, 0},
    };

    while (true) {
        int n = poll(fds, 2, -1);
        if (n <= 0) break;

        if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) break;
        if (fds[1].revents & (POLLERR | POLLHUP | POLLNVAL)) break;

        if (fds[0].revents & POLLIN) {
            ssize_t r = read(local_fd, buf, sizeof(buf));
            if (r <= 0 || !write_all(remote_fd, buf, (size_t)r)) break;
        }
        if (fds[1].revents & POLLIN) {
            ssize_t r = read(remote_fd, buf, sizeof(buf));
            if (r <= 0 || !write_all(local_fd, buf, (size_t)r)) break;
        }
    }

    close(remote_fd);
    close(local_fd);
}

static std::string companion_start_unix_proxy(const std::string &app_name,
                                              const std::string &target_host,
                                              uint16_t target_port,
                                              const std::string &preferred_name) {
    if (target_host.empty() || target_port == 0) return "";

    std::string preferred = sanitize_socket_name(preferred_name);
    if (!preferred.empty() && !is_numeric_service_name(preferred)) {
        LOGW("[companion] preferred unix name '%s' is not numeric, ignoring", preferred.c_str());
        preferred.clear();
    }

    std::string name;
    int listen_fd = -1;
    for (int attempt = 0; attempt < 32; ++attempt) {
        if (!preferred.empty() && attempt == 0) {
            name = preferred;
        } else {
            name = generate_unix_socket_name(app_name);
        }
        listen_fd = bind_abstract_unix_listener(name);
        if (listen_fd >= 0) break;
    }
    if (listen_fd < 0) {
        LOGW("[companion] failed to allocate unix proxy listener");
        return "";
    }

    std::thread([listen_fd, target_host, target_port, name]() {
        LOGI("[companion] unix proxy started: abstract=%s -> %s:%u",
             name.c_str(), target_host.c_str(), (unsigned int)target_port);
        run_unix_tcp_proxy_once(listen_fd, target_host, target_port);
        LOGI("[companion] unix proxy finished: abstract=%s", name.c_str());
    }).detach();

    return name;
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
// Companion handler (runs as root)
// Protocol:
//   1. recv app_name  -> send config JSON (empty string = not found)
//   2. recv lib_path  -> send tmp_path (empty string = error)
//      repeat until lib_path == "" (sentinel)
//   3. recv unix_proxy_mode:
//      - "on": recv target_host, target_port, preferred_name
//              -> send abstract unix socket name (empty = failure)
//      - "off": no-op
//   4. recv tracer_mode:
//      - "probe": recv target_pid + log_path + tracer_verbose_logs -> launch tracer
//      - others: no-op
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

    // Step 3: optional unix socket proxy for gadget connect mode.
    // Request:
    //   mode "on" + target_host + target_port + preferred_name
    // Response:
    //   abstract unix socket name (empty on failure)
    std::string unix_proxy_mode;
    if (read_string(client, unix_proxy_mode) && unix_proxy_mode == "on") {
        std::string target_host, preferred_name;
        uint16_t target_port = 0;
        if (read_string(client, target_host) &&
            read_u16(client, target_port) &&
            read_string(client, preferred_name)) {
            std::string unix_name = companion_start_unix_proxy(app_name, target_host,
                                                                target_port, preferred_name);
            write_string(client, unix_name);
        } else {
            write_string(client, "");
        }
    }

    // Step 4: tracer launch request (arm64 only)
#if defined(__aarch64__)
    std::string tracer_mode;
    if (read_string(client, tracer_mode) && tracer_mode == "probe") {
        uint32_t target_pid = 0;
        if (read(client, &target_pid, sizeof(target_pid)) == sizeof(target_pid)) {
            std::string log_path;
            read_string(client, log_path);
            uint8_t tracer_verbose_logs = 0;
            read_u8(client, tracer_verbose_logs);
            LOGI("[companion] launching tracer for pid %u, log=%s",
                 target_pid, log_path.c_str());
            launch_tracer((pid_t)target_pid, log_path, tracer_verbose_logs != 0);
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
        gadget_connect_override_address.clear();

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

        bool gadget_connect_mode = (cfg->gadget_interaction == "connect");
        if (!gadget_connect_mode && cfg->gadget_connect_use_unix_proxy) {
            gadget_connect_mode = true;
            LOGW("[module] gadget_connect_use_unix_proxy=true but interaction=%s; forcing connect mode",
                 cfg->gadget_interaction.c_str());
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

        // Step 3: optionally request a unix proxy for gadget connect mode.
        // The proxy runs in companion (root) and bridges:
        //   gadget unix socket <-> original tcp target (address:port).
        if (gadget_connect_mode &&
            cfg->gadget_connect_use_unix_proxy &&
            cfg->gadget_connect_address.rfind("unix:", 0) != 0) {
            if (!write_string(sock, "on") ||
                !write_string(sock, cfg->gadget_connect_address) ||
                !write_u16(sock, cfg->gadget_connect_port) ||
                !write_string(sock, cfg->gadget_connect_unix_name)) {
                LOGW("[module] failed to request unix proxy");
            } else {
                std::string unix_name;
                if (read_string(sock, unix_name) && !unix_name.empty()) {
                    gadget_connect_override_address = "unix:" + unix_name;
                    LOGI("[module] unix proxy ready for gadget connect: %s",
                         gadget_connect_override_address.c_str());
                } else {
                    LOGW("[module] unix proxy request failed, fallback to tcp connect");
                }
            }
        } else {
            if (gadget_connect_mode &&
                cfg->gadget_connect_use_unix_proxy &&
                cfg->gadget_connect_address.rfind("unix:", 0) == 0) {
                LOGI("[module] connect address already unix, skip unix proxy bridge");
            }
            write_string(sock, "off");
        }

        // Step 4: request tracer launch if configured (arm64 only)
        // The companion (root) will fork a tracer process that attaches
        // to our pid via ptrace. We send the request here in preAppSpecialize
        // because connectCompanion is only available at this stage.
#if defined(__aarch64__)
        if (cfg->tracer_mode == "probe") {
            write_string(sock, "probe");
            uint32_t my_pid = (uint32_t)getpid();
            ::write(sock, &my_pid, sizeof(my_pid));
            write_string(sock, cfg->tracer_log_path);
            write_u8(sock, cfg->tracer_verbose_logs ? 1 : 0);
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
        bool gadget_connect_mode = (cfg->gadget_interaction == "connect");
        if (!gadget_connect_mode && cfg->gadget_connect_use_unix_proxy) {
            gadget_connect_mode = true;
        }

        for (auto &lib_path : cfg->injected_libraries) {
            if (lib_path.find("/.zyg_") == std::string::npos) continue;
            // <name>.so  ->  <name>.config.so
            std::string cfg_path = lib_path.substr(0, lib_path.size() - 3) + ".config.so";

            // Build Frida gadget config JSON based on interaction type
            std::string json;
            if (gadget_connect_mode) {
                std::string connect_address = cfg->gadget_connect_address;
                if (!gadget_connect_override_address.empty()) {
                    connect_address = gadget_connect_override_address;
                }

                json = "{\"interaction\":{\"type\":\"connect\"";
                json += ",\"address\":\"" + connect_address + "\"";
                if (connect_address.rfind("unix:", 0) != 0) {
                    json += ",\"port\":" + std::to_string(cfg->gadget_connect_port);
                }
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
    std::string gadget_connect_override_address;
    // original lib_path -> tmp file path in app's data dir
    std::map<std::string, std::string> tmpfile_paths;
};

REGISTER_ZYGISK_MODULE(MyModule)
