#ifndef ZYGISKFRIDA_INJECT_STEALTH_H
#define ZYGISKFRIDA_INJECT_STEALTH_H

#include <cstdint>
#include <string>

#include "config.h"

namespace inject_stealth {

uint16_t choose_hidden_port(const target_config &cfg);

void log_hidden_port_for_config(const target_config &cfg);

// Post-load hide steps for injected libraries in app process:
// 1) unlink from linker solist
// 2) remap executable segments
void post_library_load_hide(uintptr_t load_base,
                            const std::string &lib_path,
                            const std::string &log_context);

}  // namespace inject_stealth

#endif  // ZYGISKFRIDA_INJECT_STEALTH_H
