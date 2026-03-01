#ifndef ZYGISKFRIDA_RUNTIME_TRACER_PROTOCOL_H
#define ZYGISKFRIDA_RUNTIME_TRACER_PROTOCOL_H

#include <cstdint>
#include <string>
#include <vector>

#include "../config.h"

namespace runtime {

enum class tracer_request_read_status {
    kNone = 0,
    kReady = 1,
    kMalformed = 2,
};

struct tracer_launch_request {
    uint32_t target_pid = 0;
    std::string log_path;
    bool verbose_logs = false;
    bool block_self_kill = false;
    std::vector<so_hook_config> so_hooks;
};

// Decode step-4 tracer request from companion protocol socket.
// Wire format is unchanged:
//   tracer_mode(string)
//   if mode == "probe":
//      target_pid(u32)
//      log_path(string)
//      tracer_verbose_logs(u8)
//      tracer_block_self_kill(u8)
//      num_so_hooks(u32)
//      repeat num_so_hooks:
//         so_name(string)
//         num_hooks(u32)
//         repeat num_hooks:
//            offset(u64) + return_value(i32) + branch_to(u64)
tracer_request_read_status read_tracer_launch_request(int fd, tracer_launch_request *out);

}  // namespace runtime

#endif  // ZYGISKFRIDA_RUNTIME_TRACER_PROTOCOL_H
