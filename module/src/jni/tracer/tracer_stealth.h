#ifndef ZYGISKFRIDA_TRACER_STEALTH_H
#define ZYGISKFRIDA_TRACER_STEALTH_H

#include <sys/types.h>

#include <string>
#include <vector>

namespace tracer_stealth {

using resolve_tgid_fn = pid_t (*)(pid_t tid, void *opaque);

bool is_proc_status_path(const std::string &path,
                         pid_t target_pid,
                         resolve_tgid_fn resolve_tgid,
                         void *opaque);

bool is_proc_maps_path(const std::string &path,
                       pid_t target_pid,
                       resolve_tgid_fn resolve_tgid,
                       void *opaque);

bool build_sanitized_maps_snapshot(pid_t pid,
                                   const std::vector<std::string> &protected_libs,
                                   std::string &out);

}  // namespace tracer_stealth

#endif  // ZYGISKFRIDA_TRACER_STEALTH_H
