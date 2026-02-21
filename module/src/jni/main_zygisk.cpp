#include <string>
#include <fstream>
#include <sstream>
#include <unistd.h>

#include "inject.h"
#include "config.h"
#include "log.h"
#include "zygisk.h"

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

static constexpr const char *MODULE_DIR = "/data/adb/re.zyg.fri";
static constexpr const char *FALLBACK_DIR = "/data/local/tmp/re.zyg.fri";

// ---------------------------------------------------------------------------
// Helpers: length-prefixed read/write over a blocking fd
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
    ssize_t got = read(fd, &out[0], len);
    return got == (ssize_t) len;
}

// ---------------------------------------------------------------------------
// Companion handler — runs as root, reads config and sends JSON back
// ---------------------------------------------------------------------------

static void companion_handler(int client) {
    std::string app_name;
    if (!read_string(client, app_name) || app_name.empty()) {
        LOGW("[companion] failed to read app_name");
        write_string(client, "");
        return;
    }

    // Try primary dir first, then fallback
    std::string config_path = std::string(MODULE_DIR) + "/config.json";
    std::ifstream f(config_path);
    if (!f.is_open()) {
        config_path = std::string(FALLBACK_DIR) + "/config.json";
        f.open(config_path);
    }

    if (!f.is_open()) {
        LOGW("[companion] config.json not found in %s or %s", MODULE_DIR, FALLBACK_DIR);
        write_string(client, "");
        return;
    }

    std::ostringstream ss;
    ss << f.rdbuf();
    std::string json = ss.str();
    LOGI("[companion] sending config (%zu bytes) for %s", json.size(), app_name.c_str());
    write_string(client, json);
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
        // Read app_name early (still have access to args)
        const char *raw = env->GetStringUTFChars(args->nice_name, nullptr);
        app_name = std::string(raw);
        env->ReleaseStringUTFChars(args->nice_name, raw);

        // Connect to companion (root process) and fetch config JSON
        int fd = api->connectCompanion();
        if (fd < 0) {
            LOGW("[module] connectCompanion failed, will try direct file read");
            return;
        }

        if (!write_string(fd, app_name)) {
            LOGW("[module] failed to send app_name to companion");
            close(fd);
            return;
        }

        std::string json;
        if (!read_string(fd, json)) {
            LOGW("[module] failed to read config from companion");
            close(fd);
            return;
        }
        close(fd);

        if (!json.empty()) {
            companion_json = json;
            LOGI("[module] received config from companion (%zu bytes)", json.size());
        }
    }

    void postAppSpecialize(const AppSpecializeArgs *args) override {
        if (app_name.empty()) {
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        std::optional<target_config> cfg;

        // Try config received from companion first
        if (!companion_json.empty()) {
            cfg = parse_advanced_config(companion_json, app_name);
        }

        // Fallback: direct file read (works if /data/local/tmp is used)
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
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        check_and_inject_with_config(cfg.value());
    }

 private:
    Api *api;
    JNIEnv *env;
    std::string app_name;
    std::string companion_json;
};

REGISTER_ZYGISK_MODULE(MyModule)
