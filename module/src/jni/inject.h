#ifndef ZYGISKFRIDA_INJECT_H
#define ZYGISKFRIDA_INJECT_H

#include <string>
#include "config.h"

void inject_lib(std::string const& lib_path, std::string const& logContext);
bool check_and_inject(std::string const& app_name);
void check_and_inject_with_config(target_config const& cfg);

#endif  // ZYGISKFRIDA_INJECT_H
