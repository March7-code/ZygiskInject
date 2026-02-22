#ifndef ZYGISKFRIDA_CONFIG_H
#define ZYGISKFRIDA_CONFIG_H

#include <memory>
#include <string>
#include <vector>
#include <optional>

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
    // on_load: "wait" (freeze until ready) or "resume" (continue immediately).
    std::string gadget_interaction = "listen";
    uint16_t gadget_listen_port = 0;
    std::string gadget_connect_address = "127.0.0.1";
    uint16_t gadget_connect_port = 27052;
    std::string gadget_on_load = "resume";
};

std::optional<target_config> load_config(std::string const& module_dir, std::string const& app_name);
std::optional<target_config> parse_advanced_config(std::string const& config, std::string const& app_name);

#endif  // ZYGISKFRIDA_CONFIG_H
