#include "tracer_protocol.h"

#include <unistd.h>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace runtime {

namespace {

bool read_exact(int fd, void *buf, size_t len) {
    auto *p = static_cast<uint8_t *>(buf);
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, p + off, len - off);
        if (n <= 0) return false;
        off += static_cast<size_t>(n);
    }
    return true;
}

bool read_u32(int fd, uint32_t *out) {
    return out != nullptr && read_exact(fd, out, sizeof(*out));
}

bool read_u8(int fd, uint8_t *out) {
    return out != nullptr && read_exact(fd, out, sizeof(*out));
}

bool read_string(int fd, std::string *out) {
    if (out == nullptr) return false;
    uint32_t len = 0;
    if (!read_u32(fd, &len)) return false;
    out->clear();
    if (len == 0) return true;
    out->resize(len);
    return read_exact(fd, &(*out)[0], len);
}

}  // namespace

tracer_request_read_status read_tracer_launch_request(int fd, tracer_launch_request *out) {
    if (out == nullptr) return tracer_request_read_status::kMalformed;

    tracer_launch_request req{};
    std::string tracer_mode;
    if (!read_string(fd, &tracer_mode)) {
        return tracer_request_read_status::kMalformed;
    }

    if (tracer_mode != "probe") {
        return tracer_request_read_status::kNone;
    }

    if (!read_u32(fd, &req.target_pid) ||
        !read_string(fd, &req.log_path)) {
        return tracer_request_read_status::kMalformed;
    }

    uint8_t verbose = 0;
    uint8_t block_self_kill = 0;
    if (!read_u8(fd, &verbose) ||
        !read_u8(fd, &block_self_kill)) {
        return tracer_request_read_status::kMalformed;
    }
    req.verbose_logs = (verbose != 0);
    req.block_self_kill = (block_self_kill != 0);

    uint32_t num_so_hooks = 0;
    if (!read_u32(fd, &num_so_hooks)) {
        return tracer_request_read_status::kMalformed;
    }
    req.so_hooks.reserve(num_so_hooks);

    for (uint32_t i = 0; i < num_so_hooks; ++i) {
        so_hook_config shc;
        if (!read_string(fd, &shc.so_name)) {
            return tracer_request_read_status::kMalformed;
        }

        uint32_t num_hooks = 0;
        if (!read_u32(fd, &num_hooks)) {
            return tracer_request_read_status::kMalformed;
        }
        shc.hooks.reserve(num_hooks);

        for (uint32_t j = 0; j < num_hooks; ++j) {
            hook_point hp{};
            if (!read_exact(fd, &hp.offset, sizeof(hp.offset)) ||
                !read_exact(fd, &hp.return_value, sizeof(hp.return_value)) ||
                !read_exact(fd, &hp.branch_to, sizeof(hp.branch_to))) {
                return tracer_request_read_status::kMalformed;
            }
            shc.hooks.push_back(hp);
        }

        req.so_hooks.push_back(std::move(shc));
    }

    *out = std::move(req);
    return tracer_request_read_status::kReady;
}

}  // namespace runtime
