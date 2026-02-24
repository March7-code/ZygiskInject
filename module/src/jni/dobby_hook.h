#ifndef ZYGISKFRIDA_DOBBY_HOOK_H
#define ZYGISKFRIDA_DOBBY_HOOK_H

#include <vector>
#include "config.h"

void setup_dobby_hooks(const std::vector<so_hook_config> &hooks);

#endif  // ZYGISKFRIDA_DOBBY_HOOK_H
