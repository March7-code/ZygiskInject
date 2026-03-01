#ifndef ZYGISKFRIDA_CONFIG_H
#define ZYGISKFRIDA_CONFIG_H

#include <memory>
#include <string>
#include <vector>
#include <optional>

struct hook_point {
    uint64_t offset;
    int return_value;
    // If branch_to != 0, generate a B (branch) instruction to this SO offset
    // instead of MOV X0, #N; RET.  Used for mid-function patches where RET
    // would use a stale LR.
    uint64_t branch_to = 0;
};

struct so_hook_config {
    std::string so_name;
    std::vector<hook_point> hooks;
};

struct child_gating_config {
    bool enabled;
    std::string mode;
    std::vector<std::string> injected_libraries;
};

struct target_config{
    bool enabled;
    std::string app_name;
    uint64_t start_up_delay_ms;
    std::vector<std::string> injected_libraries;
    child_gating_config child_gating;
    // Thread name used to disguise frida threads. Must be <= 15 chars.
    // Defaults to "pool-1-thread-1" if not set in config.
    std::string thread_disguise_name;

    // Frida gadget interaction settings.
    // gadget_interaction: "listen" or "connect" (recommended for stealth).
    // gadget_listen_port: TCP port for listen mode (0 = default 27042).
    // gadget_connect_address: host for connect mode (default "127.0.0.1").
    // gadget_connect_port: TCP port for connect mode (default 27052).
    // gadget_connect_use_unix_proxy: when true, module starts a UNIX socket
    //   proxy and rewrites gadget connect target to that socket.
    // gadget_connect_unix_name: optional abstract UNIX socket name to use when
    //   gadget_connect_use_unix_proxy=true. Empty = auto-generate.
    // on_load: "wait" (freeze until ready) or "resume" (continue immediately).
    std::string gadget_interaction = "listen";
    uint16_t gadget_listen_port = 0;
    std::string gadget_connect_address = "127.0.0.1";
    uint16_t gadget_connect_port = 27052;
    bool gadget_connect_use_unix_proxy = false;
    std::string gadget_connect_unix_name;
    std::string gadget_on_load = "resume";

    // Anti-cheat detection tracer settings.
    // tracer_mode: "off" (default), "probe" (log only), "block" (phase-2 hook).
    // tracer_log_path: log file for probe mode.
    // tracer_verbose_logs: when true, emit detailed per-read debug logs.
    std::string tracer_mode = "off";
    std::string tracer_log_path = "/data/local/tmp/re.zyg.fri/syscall_trace.log";
    bool tracer_verbose_logs = false;
    // When true, block exit_group/kill/tgkill syscalls (prevent self-destruction).
    // When false (default), allow them to execute but still log + capture backtrace.
    bool tracer_block_self_kill = false;

    // SO load-time patch settings (applied by tracer via ptrace).
    // Only effective when tracer_mode != "off".
    // Each entry specifies a SO name and a list of offsets to patch.
    std::vector<so_hook_config> so_load_patches;
};

std::optional<target_config> load_config(std::string const& module_dir, std::string const& app_name);
std::optional<target_config> parse_advanced_config(std::string const& config, std::string const& app_name);

#endif  // ZYGISKFRIDA_CONFIG_H
