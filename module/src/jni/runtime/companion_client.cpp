#include "companion_client.h"

#include <unistd.h>

#include <cstdint>
#include <string>

#include "../log.h"
#include "../zygisk.h"

namespace runtime {

namespace {

bool write_exact(int fd, const void *buf, size_t len) {
    const auto *p = static_cast<const uint8_t *>(buf);
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, p + off, len - off);
        if (n <= 0) return false;
        off += static_cast<size_t>(n);
    }
    return true;
}

bool write_string(int fd, const std::string &s) {
    uint32_t len = static_cast<uint32_t>(s.size());
    if (!write_exact(fd, &len, sizeof(len))) return false;
    if (len > 0 && !write_exact(fd, s.data(), len)) return false;
    return true;
}

bool read_string(int fd, std::string &out) {
    uint32_t len = 0;
    if (read(fd, &len, sizeof(len)) != static_cast<ssize_t>(sizeof(len))) return false;
    if (len == 0) {
        out.clear();
        return true;
    }
    out.resize(len);
    return read(fd, &out[0], len) == static_cast<ssize_t>(len);
}

bool write_u16(int fd, uint16_t value) {
    return write_exact(fd, &value, sizeof(value));
}

bool write_u8(int fd, uint8_t value) {
    return write_exact(fd, &value, sizeof(value));
}

bool write_u32(int fd, uint32_t value) {
    return write_exact(fd, &value, sizeof(value));
}

bool write_bytes(int fd, const void *ptr, size_t len) {
    return write_exact(fd, ptr, len);
}

bool send_tracer_request(int sock, const target_config &cfg) {
#if defined(__aarch64__)
    bool need_tracer = (cfg.tracer_mode == "probe") || !cfg.so_load_patches.empty();
    if (need_tracer) {
        if (!write_string(sock, "probe")) {
            LOGW("[module] send_tracer_request: failed to write mode=probe");
            return false;
        }
        uint32_t my_pid = static_cast<uint32_t>(getpid());
        if (!write_u32(sock, my_pid)) {
            LOGW("[module] send_tracer_request: failed to write target_pid");
            return false;
        }
        if (!write_string(sock, cfg.tracer_log_path)) {
            LOGW("[module] send_tracer_request: failed to write tracer_log_path");
            return false;
        }
        if (!write_u8(sock, cfg.tracer_verbose_logs ? 1 : 0)) {
            LOGW("[module] send_tracer_request: failed to write tracer_verbose_logs");
            return false;
        }
        if (!write_u8(sock, cfg.tracer_block_self_kill ? 1 : 0)) {
            LOGW("[module] send_tracer_request: failed to write tracer_block_self_kill");
            return false;
        }

        uint32_t num_so_hooks = static_cast<uint32_t>(cfg.so_load_patches.size());
        if (!write_u32(sock, num_so_hooks)) {
            LOGW("[module] send_tracer_request: failed to write num_so_hooks");
            return false;
        }
        for (auto &shc : cfg.so_load_patches) {
            if (!write_string(sock, shc.so_name)) {
                LOGW("[module] send_tracer_request: failed to write so_name");
                return false;
            }
            uint32_t num_hooks = static_cast<uint32_t>(shc.hooks.size());
            if (!write_u32(sock, num_hooks)) {
                LOGW("[module] send_tracer_request: failed to write num_hooks for %s",
                     shc.so_name.c_str());
                return false;
            }
            for (auto &hp : shc.hooks) {
                if (!write_bytes(sock, &hp.offset, sizeof(hp.offset))) {
                    LOGW("[module] send_tracer_request: failed to write hook offset");
                    return false;
                }
                if (!write_bytes(sock, &hp.return_value, sizeof(hp.return_value))) {
                    LOGW("[module] send_tracer_request: failed to write hook return_value");
                    return false;
                }
                if (!write_bytes(sock, &hp.branch_to, sizeof(hp.branch_to))) {
                    LOGW("[module] send_tracer_request: failed to write hook branch_to");
                    return false;
                }
            }
        }
    } else {
        if (!write_string(sock, "off")) {
            LOGW("[module] send_tracer_request: failed to write mode=off");
            return false;
        }
        return true;
    }
#else
    (void)cfg;
    if (!write_string(sock, "off")) {
        LOGW("[module] send_tracer_request: failed to write mode=off (non-arm64)");
        return false;
    }
    return true;
#endif
    return true;
}

}  // namespace

void close_companion_session(companion_session *session) {
    if (session == nullptr) return;
    if (session->fd >= 0) {
        close(session->fd);
        session->fd = -1;
    }
}

bool open_companion_session(zygisk::Api *api,
                            const std::string &app_name,
                            companion_session *out) {
    if (api == nullptr || out == nullptr) return false;

    close_companion_session(out);
    out->companion_json.clear();

    int sock = api->connectCompanion();
    if (sock < 0) {
        LOGW("[module] connectCompanion failed");
        return false;
    }

    if (!write_string(sock, app_name)) {
        LOGW("[module] failed to send app_name");
        close(sock);
        return false;
    }

    std::string json;
    if (!read_string(sock, json) || json.empty()) {
        close(sock);
        return false;
    }

    out->fd = sock;
    out->companion_json = std::move(json);
    LOGI("[module] received config (%zu bytes)", out->companion_json.size());
    return true;
}

bool finalize_companion_for_injection(companion_session *session,
                                      const target_config &cfg,
                                      std::map<std::string, std::string> *tmpfile_paths,
                                      std::string *gadget_connect_override_address,
                                      bool request_tracer) {
    if (session == nullptr || session->fd < 0) {
        LOGW("[module] finalize_companion_for_injection: invalid session");
        return false;
    }
    if (tmpfile_paths == nullptr || gadget_connect_override_address == nullptr) {
        LOGW("[module] finalize_companion_for_injection: invalid output args");
        return false;
    }

    int sock = session->fd;
    tmpfile_paths->clear();
    gadget_connect_override_address->clear();

    bool gadget_connect_mode = (cfg.gadget_interaction == "connect");
    if (!gadget_connect_mode && cfg.gadget_connect_use_unix_proxy) {
        gadget_connect_mode = true;
        LOGW("[module] gadget_connect_use_unix_proxy=true but interaction=%s; forcing connect mode",
             cfg.gadget_interaction.c_str());
    }

    // Step 2: request tmp file for each injected library.
    for (auto &lib_path : cfg.injected_libraries) {
        if (!write_string(sock, lib_path)) {
            LOGW("[module] failed to send lib path to companion: %s", lib_path.c_str());
            close_companion_session(session);
            return false;
        }

        std::string tmp_path;
        if (!read_string(sock, tmp_path) || tmp_path.empty()) {
            LOGW("[module] companion failed to copy %s", lib_path.c_str());
            continue;
        }

        LOGI("[module] tmp file ready: %s -> %s", lib_path.c_str(), tmp_path.c_str());
        (*tmpfile_paths)[lib_path] = tmp_path;
    }

    // Send empty sentinel to end lib copy session.
    if (!write_string(sock, "")) {
        LOGW("[module] failed to send lib-copy sentinel to companion");
        close_companion_session(session);
        return false;
    }

    // Step 3: optional unix proxy request.
    if (gadget_connect_mode &&
        cfg.gadget_connect_use_unix_proxy &&
        cfg.gadget_connect_address.rfind("unix:", 0) != 0) {
        if (!write_string(sock, "on") ||
            !write_string(sock, cfg.gadget_connect_address) ||
            !write_u16(sock, cfg.gadget_connect_port) ||
            !write_string(sock, cfg.gadget_connect_unix_name)) {
            LOGW("[module] failed to request unix proxy");
        } else {
            std::string unix_name;
            if (read_string(sock, unix_name) && !unix_name.empty()) {
                *gadget_connect_override_address = "unix:" + unix_name;
                LOGI("[module] unix proxy ready for gadget connect: %s",
                     gadget_connect_override_address->c_str());
            } else {
                LOGW("[module] unix proxy request failed, fallback to tcp connect");
            }
        }
    } else {
        if (gadget_connect_mode &&
            cfg.gadget_connect_use_unix_proxy &&
            cfg.gadget_connect_address.rfind("unix:", 0) == 0) {
            LOGI("[module] connect address already unix, skip unix proxy bridge");
        }
        if (!write_string(sock, "off")) {
            LOGW("[module] failed to send unix_proxy_mode=off");
            close_companion_session(session);
            return false;
        }
    }

    // Step 4: optional tracer launch request.
    if (request_tracer) {
        if (!send_tracer_request(sock, cfg)) {
            LOGW("[module] failed to send tracer request");
            close_companion_session(session);
            return false;
        }
    } else {
        if (!write_string(sock, "off")) {
            LOGW("[module] failed to send tracer_mode=off");
            close_companion_session(session);
            return false;
        }
    }

    close_companion_session(session);
    return true;
}

bool launch_tracer_now(zygisk::Api *api,
                       const std::string &app_name,
                       const target_config &cfg) {
    companion_session session{};
    if (!open_companion_session(api, app_name, &session)) {
        return false;
    }

    // Skip step-2 copy and step-3 unix proxy on this early tracer session.
    if (!write_string(session.fd, "")) {
        close_companion_session(&session);
        return false;
    }
    if (!write_string(session.fd, "off")) {
        close_companion_session(&session);
        return false;
    }
    if (!send_tracer_request(session.fd, cfg)) {
        close_companion_session(&session);
        return false;
    }

    close_companion_session(&session);
    return true;
}

}  // namespace runtime
