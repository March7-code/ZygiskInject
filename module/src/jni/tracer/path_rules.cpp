#include "path_rules.h"

bool path_rule_matches(const std::vector<path_rule> &rules,
                       const std::string &caller_lib,
                       const std::string &path,
                       const std::string &sc_name) {
    for (auto &r : rules) {
        if (!r.library.empty() &&
            caller_lib.find(r.library) == std::string::npos)
            continue;
        if (!r.syscall_name.empty() && r.syscall_name != sc_name)
            continue;
        if (!r.path_pattern.empty() &&
            path.find(r.path_pattern) == std::string::npos)
            continue;
        return true;
    }
    return false;
}
