#include "inject_stealth.h"

#include <inttypes.h>

#include "log.h"
#include "remapper.h"
#include "solist_patch.h"

namespace inject_stealth {

uint16_t choose_hidden_port(const target_config &cfg) {
    if (cfg.gadget_interaction == "connect" && cfg.gadget_connect_port > 0) {
        return cfg.gadget_connect_port;
    }
    return cfg.gadget_listen_port > 0 ? cfg.gadget_listen_port : 27042;
}

void log_hidden_port_for_config(const target_config &cfg) {
    uint16_t hidden_port = choose_hidden_port(cfg);
    LOGI("[net_filter] hiding port %u from /proc/net/tcp", hidden_port);
}

void post_library_load_hide(uintptr_t load_base,
                            const std::string &lib_path,
                            const std::string &log_context) {
    if (load_base != 0) {
        solist_remove_lib(load_base);
    } else {
        LOGW("%sFailed to get load address: %s", log_context.c_str(), lib_path.c_str());
    }

    remap_lib(lib_path);
}

}  // namespace inject_stealth
