#include "zygisk_entry.h"

#include <unistd.h>
#include <fcntl.h>

#include <cerrno>
#include <cstring>
#include <optional>
#include <string>
#include <utility>

#include "injector.h"
#include "../config.h"
#include "../log.h"

namespace runtime {

namespace {

constexpr const char *kFallbackConfigDir = "/data/local/tmp/re.zyg.fri";

bool should_request_tracer(const target_config &cfg) {
#if defined(__aarch64__)
    return (cfg.tracer_mode == "probe") || !cfg.so_load_patches.empty();
#else
    (void)cfg;
    return false;
#endif
}

bool lib_path_requires_companion_copy(const std::string &lib_path) {
    // App process usually cannot directly dlopen files from Magisk module dir.
    return lib_path.rfind("/data/adb/", 0) == 0;
}

bool has_libs_requiring_companion_copy(const target_config &cfg) {
    for (const auto &lib_path : cfg.injected_libraries) {
        if (lib_path_requires_companion_copy(lib_path)) {
            return true;
        }
    }
    return false;
}

bool all_required_libs_materialized(const target_config &cfg,
                                    const std::map<std::string, std::string> &tmpfile_paths) {
    for (const auto &lib_path : cfg.injected_libraries) {
        if (!lib_path_requires_companion_copy(lib_path)) continue;
        if (tmpfile_paths.find(lib_path) == tmpfile_paths.end()) {
            return false;
        }
    }
    return true;
}

void write_gadget_sidecar_configs(const target_config &cfg,
                                  const std::string &gadget_connect_override_address) {
    bool gadget_connect_mode = (cfg.gadget_interaction == "connect");
    if (!gadget_connect_mode && cfg.gadget_connect_use_unix_proxy) {
        gadget_connect_mode = true;
    }

    for (auto &lib_path : cfg.injected_libraries) {
        if (lib_path.find("/.zyg_") == std::string::npos) continue;

        std::string cfg_path = lib_path.substr(0, lib_path.size() - 3) + ".config.so";
        std::string json;

        if (gadget_connect_mode) {
            std::string connect_address = cfg.gadget_connect_address;
            if (!gadget_connect_override_address.empty()) {
                connect_address = gadget_connect_override_address;
            }

            json = "{\"interaction\":{\"type\":\"connect\"";
            json += ",\"address\":\"" + connect_address + "\"";
            if (connect_address.rfind("unix:", 0) != 0) {
                json += ",\"port\":" + std::to_string(cfg.gadget_connect_port);
            }
            json += ",\"on_load\":\"" + cfg.gadget_on_load + "\"";
            json += "}}";
        } else {
            json = "{\"interaction\":{\"type\":\"listen\"";
            if (cfg.gadget_listen_port > 0) {
                json += ",\"address\":\"127.0.0.1\"";
                json += ",\"port\":" + std::to_string(cfg.gadget_listen_port);
            }
            json += ",\"on_load\":\"" + cfg.gadget_on_load + "\"";
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
}

}  // namespace

void zygisk_entry::on_load(zygisk::Api *api, JNIEnv *env) {
    api_ = api;
    env_ = env;
}

void zygisk_entry::pre_app_specialize(zygisk::AppSpecializeArgs *args) {
    const char *raw = env_->GetStringUTFChars(args->nice_name, nullptr);
    app_name_ = std::string(raw);
    env_->ReleaseStringUTFChars(args->nice_name, raw);

    close_companion_session(&companion_session_);
    prepared_tmpfile_paths_.clear();
    prepared_gadget_connect_override_address_.clear();
    prepared_companion_success_ = false;

    if (!open_companion_session(api_, app_name_, &companion_session_)) {
        return;
    }

    // tracer must start as early as possible; launch it immediately when enabled.
    auto cfg = parse_advanced_config(companion_session_.companion_json, app_name_);
    if (cfg.has_value() && should_request_tracer(cfg.value())) {
        if (!launch_tracer_now(api_, app_name_, cfg.value())) {
            LOGW("[module] early tracer launch request failed");
        }
    }

    // Materialize injected libs before app startup. Later process permissions may
    // no longer allow reading module dir files directly.
    if (cfg.has_value()) {
        target_config prepare_cfg = cfg.value();
        bool need_companion_copy = has_libs_requiring_companion_copy(prepare_cfg);
        if (need_companion_copy) {
            std::map<std::string, std::string> tmpfile_paths;
            std::string gadget_connect_override_address;
            if (!finalize_companion_for_injection(&companion_session_, prepare_cfg,
                                                  &tmpfile_paths,
                                                  &gadget_connect_override_address,
                                                  false)) {
                LOGW("[module] pre stage materialization failed");
            } else if (!all_required_libs_materialized(prepare_cfg, tmpfile_paths)) {
                LOGW("[module] pre stage materialization incomplete");
            } else {
                prepared_tmpfile_paths_ = std::move(tmpfile_paths);
                prepared_gadget_connect_override_address_ =
                    std::move(gadget_connect_override_address);
                prepared_companion_success_ = true;
            }
        }
    }

    // Keep config json only; use a fresh companion session in post stage.
    close_companion_session(&companion_session_);
}

void zygisk_entry::post_app_specialize(const zygisk::AppSpecializeArgs *args) {
    (void)args;

    if (app_name_.empty()) {
        close_companion_session(&companion_session_);
        api_->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
        return;
    }

    std::optional<target_config> cfg;
    if (!companion_session_.companion_json.empty()) {
        cfg = parse_advanced_config(companion_session_.companion_json, app_name_);
    }
    if (!cfg.has_value()) {
        close_companion_session(&companion_session_);
        cfg = load_config(kFallbackConfigDir, app_name_);
    }
    if (!cfg.has_value()) {
        api_->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
        return;
    }

    LOGI("App detected: %s", app_name_.c_str());

    if (!cfg->enabled) {
        LOGI("Injection disabled for %s", app_name_.c_str());
        close_companion_session(&companion_session_);
        api_->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
        return;
    }

    target_config inject_cfg = cfg.value();
    bool need_companion_copy = has_libs_requiring_companion_copy(inject_cfg);

    if (prepared_companion_success_) {
        for (auto &lib_path : inject_cfg.injected_libraries) {
            auto it = prepared_tmpfile_paths_.find(lib_path);
            if (it != prepared_tmpfile_paths_.end()) {
                LOGI("[module] using tmp path %s for %s",
                     it->second.c_str(), lib_path.c_str());
                lib_path = it->second;
            }
        }
        write_gadget_sidecar_configs(inject_cfg, prepared_gadget_connect_override_address_);
    } else if (need_companion_copy) {
        LOGW("[module] no pre-materialized libs available, cannot inject from /data/adb");
        close_companion_session(&companion_session_);
        api_->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
        return;
    }

    close_companion_session(&companion_session_);
    prepared_tmpfile_paths_.clear();
    prepared_gadget_connect_override_address_.clear();
    prepared_companion_success_ = false;

    start_injection(std::move(inject_cfg));
}

}  // namespace runtime
