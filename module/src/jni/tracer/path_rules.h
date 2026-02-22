#ifndef ZYGISKFRIDA_TRACER_PATH_RULES_H
#define ZYGISKFRIDA_TRACER_PATH_RULES_H

#include <string>
#include <vector>

// Path matching rules for phase-2 (block mode).
// In phase-1 (probe mode), these are not used — all syscalls are logged.

struct path_rule {
    std::string library;       // source .so name (e.g. "libmsec.so"), empty = any
    std::string path_pattern;  // substring match in the syscall path argument
    std::string syscall_name;  // "openat", "faccessat", etc., empty = any
};

// Check if a syscall matches any blocking rule.
bool path_rule_matches(const std::vector<path_rule> &rules,
                       const std::string &caller_lib,
                       const std::string &path,
                       const std::string &sc_name);

#endif // ZYGISKFRIDA_TRACER_PATH_RULES_H
