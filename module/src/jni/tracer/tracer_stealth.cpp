#include "tracer_stealth.h"

#include <cstdio>

namespace tracer_stealth {
namespace {

bool is_proc_task_status_path(const std::string &path,
                              const std::string &prefix) {
    // Match "<prefix><tid>/status", where <tid> is decimal.
    if (path.rfind(prefix, 0) != 0) return false;

    size_t tid_start = prefix.size();
    size_t slash_pos = path.find('/', tid_start);
    if (slash_pos == std::string::npos) return false;
    if (slash_pos + 7 != path.size()) return false;
    if (path.compare(slash_pos, 7, "/status") != 0) return false;

    if (slash_pos == tid_start) return false;
    for (size_t i = tid_start; i < slash_pos; ++i) {
        const char c = path[i];
        if (c < '0' || c > '9') return false;
    }
    return true;
}

bool parse_proc_numeric_leaf(const std::string &path,
                             const char *leaf,
                             pid_t *out_pid) {
    const std::string prefix = "/proc/";
    if (path.rfind(prefix, 0) != 0) return false;

    const size_t num_start = prefix.size();
    const size_t slash_pos = path.find('/', num_start);
    if (slash_pos == std::string::npos) return false;
    if (slash_pos + 1 >= path.size()) return false;

    const std::string suffix = std::string("/") + leaf;
    if (path.compare(slash_pos, suffix.size(), suffix) != 0) return false;
    if (slash_pos + suffix.size() != path.size()) return false;

    if (slash_pos == num_start) return false;
    int value = 0;
    for (size_t i = num_start; i < slash_pos; ++i) {
        const char c = path[i];
        if (c < '0' || c > '9') return false;
        value = value * 10 + (c - '0');
    }
    if (value <= 0) return false;
    if (out_pid) *out_pid = (pid_t)value;
    return true;
}

void sanitize_maps_line(std::string &line,
                        const std::vector<std::string> &protected_libs) {
    bool is_protected = false;
    for (const auto &lib : protected_libs) {
        if (line.find(lib) != std::string::npos) {
            is_protected = true;
            break;
        }
    }
    if (!is_protected) return;

    // maps line: "<start>-<end> <perms> ..."
    size_t perms_pos = line.find(' ');
    if (perms_pos == std::string::npos) return;
    while (perms_pos < line.size() && line[perms_pos] == ' ') {
        ++perms_pos;
    }

    if (perms_pos + 2 < line.size() && line[perms_pos + 2] == 'x') {
        line[perms_pos + 2] = '-';
    }
}

}  // namespace

bool is_proc_status_path(const std::string &path,
                         pid_t target_pid,
                         resolve_tgid_fn resolve_tgid,
                         void *opaque) {
    if (path == "/proc/self/status") return true;
    if (path == "/proc/thread-self/status") return true;

    if (target_pid > 0) {
        char buf[64];
        snprintf(buf, sizeof(buf), "/proc/%d/status", target_pid);
        if (path == buf) return true;
    }

    pid_t proc_pid = 0;
    if (parse_proc_numeric_leaf(path, "status", &proc_pid)) {
        if (target_pid > 0 && proc_pid == target_pid) return true;
        if (target_pid > 0 && resolve_tgid && resolve_tgid(proc_pid, opaque) == target_pid) {
            return true;
        }
    }

    if (is_proc_task_status_path(path, "/proc/self/task/")) return true;

    if (target_pid > 0) {
        char buf[64];
        snprintf(buf, sizeof(buf), "/proc/%d/task/", target_pid);
        if (is_proc_task_status_path(path, buf)) return true;
    }

    return false;
}

bool is_proc_maps_path(const std::string &path,
                       pid_t target_pid,
                       resolve_tgid_fn resolve_tgid,
                       void *opaque) {
    if (path == "/proc/self/maps") return true;
    if (path == "/proc/thread-self/maps") return true;

    if (target_pid > 0) {
        char buf[64];
        snprintf(buf, sizeof(buf), "/proc/%d/maps", target_pid);
        if (path == buf) return true;
    }

    pid_t proc_pid = 0;
    if (parse_proc_numeric_leaf(path, "maps", &proc_pid)) {
        if (target_pid > 0 && proc_pid == target_pid) return true;
        if (target_pid > 0 && resolve_tgid && resolve_tgid(proc_pid, opaque) == target_pid) {
            return true;
        }
    }

    return false;
}

bool build_sanitized_maps_snapshot(pid_t pid,
                                   const std::vector<std::string> &protected_libs,
                                   std::string &out) {
    out.clear();

    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *fp = fopen(maps_path, "r");
    if (!fp) return false;

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        std::string text(line);
        sanitize_maps_line(text, protected_libs);
        out += text;
    }
    fclose(fp);

    return !out.empty();
}

}  // namespace tracer_stealth
