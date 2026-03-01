#ifndef ZYGISKFRIDA_RUNTIME_INJECTOR_H
#define ZYGISKFRIDA_RUNTIME_INJECTOR_H

#include <functional>

#include "../config.h"

namespace runtime {

// Called after wait + delay, before actual library injection.
// Return false to cancel injection.
using injector_prepare = std::function<bool(target_config &)>;

// Start asynchronous injection pipeline:
// wait_for_init -> child_gating -> delay -> prepare(optional) -> inject libs.
void start_injection(target_config cfg, injector_prepare prepare = injector_prepare{});

}  // namespace runtime

#endif  // ZYGISKFRIDA_RUNTIME_INJECTOR_H

