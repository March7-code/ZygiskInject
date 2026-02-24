#include "syscall_handler.h"
#include "arch.h"

#include <algorithm>
#include <cerrno>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <map>
#include <set>
#include <string>
#include <vector>

#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <signal.h>
#include <unistd.h>

#include "../log.h"

#define TAG "[syscall_handler] "

static FILE *g_log_fp = nullptr;
static pid_t g_target_pid = 0;
static bool g_verbose_logs = false;
static bool g_block_self_kill = false;

// =========================================================================
// SO load-time hook: patch functions via ptrace before .init_array runs
// =========================================================================
// When the linker opens a target SO, we track the fd. On close(fd), the SO
// is fully mmap'd but constructors haven't run yet. We read /proc/<pid>/maps
// to find the base address, then PTRACE_POKEDATA to overwrite function
// prologues with "MOV X0, #N; RET".

struct so_hook_state {
    std::string so_name;
    std::vector<hook_point> hooks;
    bool done = false;
};
static std::vector<so_hook_state> g_so_hooks;
static bool g_all_so_hooks_done = false;
static uint64_t g_last_so_hook_probe_ms = 0;
// g_so_hook_fds declared after tracked_fd_key below

static uint64_t make_arm64_patch(int return_value) {
    // ARM64 little-endian: first 4 bytes = MOV X0, #imm; next 4 bytes = RET
    uint32_t mov_insn;
    if (return_value >= 0) {
        // MOV X0, #return_value  (MOVZ X0, #imm, LSL #0)
        mov_insn = 0xD2800000 | ((uint32_t)(return_value & 0xFFFF) << 5);
    } else {
        // MOV X0, #return_value  (MOVN X0, #~imm)
        mov_insn = 0x92800000 | ((uint32_t)(~return_value & 0xFFFF) << 5);
    }
    uint32_t ret_insn = 0xD65F03C0;  // RET
    return (uint64_t)ret_insn << 32 | mov_insn;
}

static uintptr_t find_so_load_bias_in_maps(pid_t pid, const char *so_name) {
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *fp = fopen(maps_path, "r");
    if (!fp) return 0;

    char line[512];
    uintptr_t best_bias = 0;
    bool have_any = false;
    uintptr_t exec_bias = 0;
    bool have_exec = false;
    while (fgets(line, sizeof(line), fp)) {
        if (!strstr(line, so_name)) continue;
        uintptr_t start = 0;
        uintptr_t end = 0;
        char perms[5] = {0};
        unsigned long long file_off = 0;
        if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %4s %llx",
                   &start, &end, perms, &file_off) < 4) {
            continue;
        }

        uintptr_t bias = start - (uintptr_t)file_off;
        if (!have_any || bias < best_bias) {
            best_bias = bias;
            have_any = true;
        }
        if (strchr(perms, 'x')) {
            exec_bias = bias;
            have_exec = true;
        }
    }
    fclose(fp);
    if (have_exec) return exec_bias;
    if (have_any) return best_bias;
    return 0;
}

static bool apply_so_hooks_at_load_bias(pid_t pid,
                                        size_t hook_idx,
                                        uintptr_t load_bias,
                                        const char *reason) {
    so_hook_state &state = g_so_hooks[hook_idx];
    if (state.done) return true;

    LOGI(TAG "so_hook: %s loaded via %s, load_bias=0x%" PRIxPTR,
         state.so_name.c_str(), reason, load_bias);

    bool all_ok = true;
    for (auto &hp : state.hooks) {
        uint64_t target_addr = load_bias + hp.offset;

        if (hp.branch_to != 0) {
            // Generate ARM64 B (unconditional branch) to branch_to offset.
            // B encoding: 0x14000000 | (imm26), where imm26 = (target - pc) / 4
            int64_t rel = (int64_t)(hp.branch_to - hp.offset);
            int32_t imm26 = (int32_t)(rel / 4) & 0x03FFFFFF;
            uint32_t b_insn = 0x14000000 | (uint32_t)imm26;
            uint32_t nop_insn = 0xD503201F;  // NOP (pad second word)
            uint64_t patch = (uint64_t)nop_insn << 32 | b_insn;

            if (ptrace(PTRACE_POKEDATA, pid, (void *)target_addr, (void *)patch) == 0) {
                LOGI(TAG "so_hook: patched 0x%" PRIx64 " at 0x%" PRIx64 " -> B 0x%" PRIx64,
                     hp.offset, target_addr, (uint64_t)(load_bias + hp.branch_to));
            } else {
                LOGE(TAG "so_hook: POKEDATA failed at 0x%" PRIx64 ": %s",
                     target_addr, strerror(errno));
                all_ok = false;
            }
        } else {
            uint64_t patch = make_arm64_patch(hp.return_value);

            if (ptrace(PTRACE_POKEDATA, pid, (void *)target_addr, (void *)patch) == 0) {
                LOGI(TAG "so_hook: patched 0x%" PRIx64 " at 0x%" PRIx64 " -> return %d",
                     hp.offset, target_addr, hp.return_value);
            } else {
                LOGE(TAG "so_hook: POKEDATA failed at 0x%" PRIx64 ": %s",
                     target_addr, strerror(errno));
                all_ok = false;
            }
        }
    }

    state.done = all_ok;
    if (!all_ok) {
        LOGW(TAG "so_hook: %s patch incomplete, will retry if SO is reopened",
             state.so_name.c_str());
    }
    g_all_so_hooks_done = true;
    for (auto &s : g_so_hooks) {
        if (!s.done) { g_all_so_hooks_done = false; break; }
    }
    return all_ok;
}

static void apply_so_hooks_via_ptrace(pid_t pid, size_t hook_idx) {
    so_hook_state &state = g_so_hooks[hook_idx];
    uintptr_t load_bias = find_so_load_bias_in_maps(pid, state.so_name.c_str());
    if (load_bias == 0) {
        LOGW(TAG "so_hook: %s not found in maps yet", state.so_name.c_str());
        return;
    }
    (void)apply_so_hooks_at_load_bias(pid, hook_idx, load_bias, "maps");
}

// Forward declarations
static void refresh_maps_cache(pid_t pid);
static bool read_tracee_mem(pid_t pid, uint64_t addr, void *out, size_t len);
static bool write_tracee_mem(pid_t pid, uint64_t addr, const void *data, size_t len);

// Keep ptrace memory accesses robust on ARM64 with top-byte tags.
static inline uint64_t untag_user_addr(uint64_t addr) {
    return addr & 0x00FFFFFFFFFFFFFFULL;
}

// =========================================================================
// TracerPid hiding: fd tracking
// =========================================================================
// Track fds that were opened on /proc/self/status or /proc/<pid>/status.
// When read() is called on these fds, we need to tamper with the buffer.

struct tracked_fd_key {
    pid_t tgid;
    uint64_t fd;

    bool operator<(const tracked_fd_key &other) const {
        if (tgid != other.tgid) return tgid < other.tgid;
        return fd < other.fd;
    }
};

static std::map<pid_t, pid_t> g_tid_to_tgid_cache;

static pid_t read_tgid_from_status_file(const char *status_path, pid_t fallback) {
    FILE *fp = fopen(status_path, "r");
    if (!fp) return 0;

    char line[256];
    pid_t tgid = fallback;
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "Tgid:", 5) == 0) {
            int parsed = 0;
            if (sscanf(line + 5, "%d", &parsed) == 1 && parsed > 0) {
                tgid = (pid_t)parsed;
            }
            break;
        }
    }
    fclose(fp);
    return tgid;
}

static pid_t resolve_tracee_tgid(pid_t tid) {
    auto it = g_tid_to_tgid_cache.find(tid);
    if (it != g_tid_to_tgid_cache.end()) return it->second;

    char status_path[64];
    snprintf(status_path, sizeof(status_path), "/proc/%d/status", tid);
    pid_t tgid = read_tgid_from_status_file(status_path, tid);

    // For non-leader threads, /proc/<tid>/status may not exist on Android.
    // Try /proc/<target_pid>/task/<tid>/status as a fallback.
    if (tgid == 0 && g_target_pid > 0 && tid != g_target_pid) {
        snprintf(status_path, sizeof(status_path), "/proc/%d/task/%d/status",
                 g_target_pid, tid);
        tgid = read_tgid_from_status_file(status_path, tid);
    }

    if (tgid <= 0) {
        tgid = tid;
    }

    g_tid_to_tgid_cache[tid] = tgid;
    return tgid;
}

static inline tracked_fd_key make_fd_key(pid_t tid, uint64_t fd) {
    return tracked_fd_key{resolve_tracee_tgid(tid), fd};
}

static std::set<tracked_fd_key> g_status_fds;  // (tgid, fd) for proc status

// SO hook fd tracking (declared here after tracked_fd_key is defined)
static std::map<tracked_fd_key, size_t> g_so_hook_fds;  // fd -> index into g_so_hooks
// Fallback index for cases where tgid resolution briefly fails on worker tids.
static std::map<uint64_t, size_t> g_so_hook_fds_raw;    // fd -> index into g_so_hooks

static std::string normalize_path_basename(const std::string &path) {
    const char *base = strrchr(path.c_str(), '/');
    base = base ? base + 1 : path.c_str();
    std::string name(base);
    static const std::string kDeletedSuffix = " (deleted)";
    if (name.size() > kDeletedSuffix.size() &&
        name.compare(name.size() - kDeletedSuffix.size(),
                     kDeletedSuffix.size(), kDeletedSuffix) == 0) {
        name.resize(name.size() - kDeletedSuffix.size());
    }
    return name;
}

static bool match_pending_so_hook_by_path(const std::string &path, size_t *out_idx) {
    std::string basename = normalize_path_basename(path);
    for (size_t i = 0; i < g_so_hooks.size(); i++) {
        if (!g_so_hooks[i].done && g_so_hooks[i].so_name == basename) {
            if (out_idx) *out_idx = i;
            return true;
        }
    }
    return false;
}

static bool lookup_so_hook_idx_by_fd(pid_t tid, uint64_t fd, size_t *out_idx) {
    tracked_fd_key key = make_fd_key(tid, fd);
    auto it = g_so_hook_fds.find(key);
    if (it != g_so_hook_fds.end()) {
        if (out_idx) *out_idx = it->second;
        return true;
    }

    // Fallback to raw-fd map for cases where fd tracking crosses tids.
    auto raw_it = g_so_hook_fds_raw.find(fd);
    if (raw_it != g_so_hook_fds_raw.end()) {
        if (out_idx) *out_idx = raw_it->second;
        return true;
    }
    return false;
}

static void erase_so_hook_fd_tracking(pid_t tid, uint64_t fd) {
    tracked_fd_key key = make_fd_key(tid, fd);
    g_so_hook_fds.erase(key);
    g_so_hook_fds_raw.erase(fd);
}

static bool is_proc_task_status_path(const std::string &path,
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
        char c = path[i];
        if (c < '0' || c > '9') return false;
    }
    return true;
}

static bool parse_proc_numeric_leaf(const std::string &path,
                                    const char *leaf,
                                    pid_t *out_pid) {
    const std::string prefix = "/proc/";
    if (path.rfind(prefix, 0) != 0) return false;

    size_t num_start = prefix.size();
    size_t slash_pos = path.find('/', num_start);
    if (slash_pos == std::string::npos) return false;
    if (slash_pos + 1 >= path.size()) return false;

    const std::string suffix = std::string("/") + leaf;
    if (path.compare(slash_pos, suffix.size(), suffix) != 0) return false;
    if (slash_pos + suffix.size() != path.size()) return false;

    if (slash_pos == num_start) return false;
    int value = 0;
    for (size_t i = num_start; i < slash_pos; ++i) {
        char c = path[i];
        if (c < '0' || c > '9') return false;
        value = value * 10 + (c - '0');
    }
    if (value <= 0) return false;
    if (out_pid) *out_pid = (pid_t)value;
    return true;
}

// Check if a path is one of:
// - /proc/self/status
// - /proc/<target_pid>/status
// - /proc/self/task/<tid>/status
// - /proc/<target_pid>/task/<tid>/status
static bool is_proc_status_path(const std::string &path) {
    if (path == "/proc/self/status") return true;
    if (path == "/proc/thread-self/status") return true;

    char buf[64];
    snprintf(buf, sizeof(buf), "/proc/%d/status", g_target_pid);
    if (path == buf) return true;

    pid_t proc_pid = 0;
    if (parse_proc_numeric_leaf(path, "status", &proc_pid)) {
        if (proc_pid == g_target_pid) return true;
        if (resolve_tracee_tgid(proc_pid) == g_target_pid) return true;
    }

    if (is_proc_task_status_path(path, "/proc/self/task/")) return true;

    snprintf(buf, sizeof(buf), "/proc/%d/task/", g_target_pid);
    if (is_proc_task_status_path(path, buf)) return true;

    return false;
}

// Set of pids currently waiting for syscall-exit (read on status fd)
static std::set<pid_t> g_waiting_read_exit;

struct pending_exit_state {
    uint64_t nr = 0;
    uint64_t args[6] = {0, 0, 0, 0, 0, 0};
};
static std::map<pid_t, pending_exit_state> g_pending_exit;

static inline void remember_pending_exit(pid_t tid, const tracer_regs &regs) {
    pending_exit_state st{};
    st.nr = tracer_get_syscall_nr(regs);
    for (int i = 0; i < 6; ++i) {
        st.args[i] = tracer_get_arg(regs, i);
    }
    g_pending_exit[tid] = st;
}

// =========================================================================
// ELF checksum bypass: /proc/self/maps tampering
// =========================================================================
// The detection code (detect_frida_memdiskcompare) reads /proc/self/maps
// to find executable segments of protected libraries, then compares the
// in-memory checksum against a pre-computed disk checksum.  Frida modifies
// the .text section in memory, causing a mismatch.
//
// Strategy: intercept read() on /proc/self/maps fds and change the
// permission field from "r-xp" to "r--p" for protected library lines.
// This makes scan_executable_segments() skip the checksum comparison
// because buf[2] != 'x'.

// fds pointing to /proc/self/maps (tracked like status fds)
static std::set<tracked_fd_key> g_maps_fds;
static uint64_t g_maps_stage_start_ms = 0;

// Library names to protect (basenames). Populated at init.
static std::vector<std::string> g_protected_libs;
struct maps_fd_state {
    bool tamper_enabled = false;
    size_t stream_pos = 0;
    std::string sanitized_maps;
};
static std::map<tracked_fd_key, maps_fd_state> g_maps_fd_states;

// Check if a path is /proc/self/maps or /proc/<pid>/maps
static bool is_proc_maps_path(const std::string &path) {
    if (path == "/proc/self/maps") return true;
    if (path == "/proc/thread-self/maps") return true;
    char buf[64];
    snprintf(buf, sizeof(buf), "/proc/%d/maps", g_target_pid);
    if (path == buf) return true;

    pid_t proc_pid = 0;
    if (parse_proc_numeric_leaf(path, "maps", &proc_pid)) {
        if (proc_pid == g_target_pid) return true;
        if (resolve_tracee_tgid(proc_pid) == g_target_pid) return true;
    }
    return false;
}

static void sanitize_maps_line(std::string &line) {
    bool is_protected = false;
    for (const auto &lib : g_protected_libs) {
        if (line.find(lib) != std::string::npos) {
            is_protected = true;
            break;
        }
    }
    if (!is_protected) return;

    // maps line: "<start>-<end> <perms> ..."
    size_t perms_pos = line.find(' ');
    if (perms_pos == std::string::npos) return;
    while (perms_pos < line.size() && line[perms_pos] == ' ')
        perms_pos++;

    if (perms_pos + 2 < line.size() && line[perms_pos + 2] == 'x') {
        line[perms_pos + 2] = '-';
    }
}

static bool build_sanitized_maps_snapshot(pid_t pid, std::string &out) {
    out.clear();

    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *fp = fopen(maps_path, "r");
    if (!fp) return false;

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        std::string s(line);
        sanitize_maps_line(s);
        out += s;
    }
    fclose(fp);
    return !out.empty();
}

// Tamper a read() buffer from /proc/self/maps: for lines containing a
// protected library name with executable permission, change 'x' to '-'
// in the permission field so the detection skips checksum comparison.
//
// Maps line format: "start-end perms offset dev inode pathname\n"
// Example: "7a8c000000-7a8c100000 r-xp 00000000 fe:06 123 /apex/.../libc.so\n"
// We change "r-xp" to "r--p" for lines matching protected libs.
static bool tamper_maps_read_chunk(pid_t pid, uint64_t buf_addr, size_t bytes_read) {
    if (bytes_read == 0) return false;

    std::vector<char> buf(bytes_read);
    if (!read_tracee_mem(pid, buf_addr, buf.data(), bytes_read))
        return false;

    bool tampered = false;
    size_t i = 0;
    while (i < bytes_read) {
        // Find end of current line
        size_t line_start = i;
        while (i < bytes_read && buf[i] != '\n') i++;
        size_t line_end = i;
        if (i < bytes_read) i++;  // skip '\n'

        size_t line_len = line_end - line_start;
        if (line_len < 20) continue;  // too short to be a valid maps line

        // Check if this line contains any protected library name
        bool is_protected = false;
        for (auto &lib : g_protected_libs) {
            // Search for the library name in this line
            for (size_t j = line_start; j + lib.size() <= line_end; j++) {
                if (memcmp(buf.data() + j, lib.data(), lib.size()) == 0) {
                    is_protected = true;
                    break;
                }
            }
            if (is_protected) break;
        }
        if (!is_protected) continue;

        // Find the permissions field (after the first space)
        // Format: "addr-addr perms ..."
        size_t space_pos = line_start;
        while (space_pos < line_end && buf[space_pos] != ' ') space_pos++;
        if (space_pos >= line_end) continue;
        space_pos++;  // skip space

        // perms is 4 chars: rwxp/rwxs
        if (space_pos + 3 >= line_end) continue;

        // Check if this is an executable mapping (perms[2] == 'x')
        if (buf[space_pos + 2] == 'x') {
            buf[space_pos + 2] = '-';  // r-xp -> r--p
            tampered = true;
            if (g_verbose_logs) {
                LOGI(TAG "maps_bypass: hid executable perm for protected lib");
            }
        }
    }

    if (tampered) {
        if (!write_tracee_mem(pid, buf_addr, buf.data(), bytes_read)) {
            LOGE(TAG "maps_bypass: POKEDATA failed");
            return false;
        }
    }
    return tampered;
}

// Stream-aware maps tamper:
// Many anti-Frida samples read /proc/self/maps byte-by-byte via read(fd, &c, 1).
// Chunk-only tampering misses that pattern, so we keep a per-fd sanitized
// snapshot and rewrite returned bytes by stream position.
static bool tamper_maps_read_stream(pid_t pid,
                                    uint64_t fd_val,
                                    uint64_t buf_addr,
                                    size_t bytes_read) {
    if (bytes_read == 0) return false;

    tracked_fd_key key = make_fd_key(pid, fd_val);
    auto it = g_maps_fd_states.find(key);
    if (it == g_maps_fd_states.end()) {
        return tamper_maps_read_chunk(pid, buf_addr, bytes_read);
    }

    maps_fd_state &state = it->second;
    if (!state.tamper_enabled) {
        if (g_verbose_logs && g_log_fp) {
            fprintf(g_log_fp,
                    "[maps_bypass] stream skip (disabled): tid=%d tgid=%d fd=%llu bytes=%zu pos=%zu\n",
                    pid, key.tgid, (unsigned long long)fd_val, bytes_read, state.stream_pos);
            fflush(g_log_fp);
        }
        state.stream_pos += bytes_read;
        return false;
    }

    if (state.sanitized_maps.empty()) {
        if (!build_sanitized_maps_snapshot(g_target_pid, state.sanitized_maps)) {
            // Fallback to chunk mode if snapshot cannot be built.
            state.stream_pos += bytes_read;
            return tamper_maps_read_chunk(pid, buf_addr, bytes_read);
        }
    }

    std::vector<char> original(bytes_read);
    if (!read_tracee_mem(pid, buf_addr, original.data(), bytes_read))
        return false;

    std::vector<char> patched = original;
    if (state.stream_pos < state.sanitized_maps.size()) {
        size_t copy_len = std::min(bytes_read,
                                   state.sanitized_maps.size() - state.stream_pos);
        memcpy(patched.data(),
               state.sanitized_maps.data() + state.stream_pos,
               copy_len);
    }
    state.stream_pos += bytes_read;

    if (memcmp(original.data(), patched.data(), bytes_read) == 0)
        return false;

    if (!write_tracee_mem(pid, buf_addr, patched.data(), bytes_read)) {
        LOGE(TAG "maps_bypass: stream POKEDATA failed");
        return false;
    }
    return true;
}

// =========================================================================
// Level-1 fast filter: path prefix check
// =========================================================================
static const char *g_interesting_prefixes[] = {
    "/proc/",
    "/data/local/tmp",
    "/data/adb/",
    "/sys/",
    nullptr
};

static bool peek_prefix(pid_t pid, uint64_t addr, char out[8]) {
    if (addr == 0) return false;
    addr = untag_user_addr(addr);
    errno = 0;
    long word = ptrace(PTRACE_PEEKDATA, pid, (void*)addr, nullptr);
    if (errno != 0) return false;
    memcpy(out, &word, 8);
    return true;
}

static bool is_interesting_prefix(const char prefix[8]) {
    for (int i = 0; g_interesting_prefixes[i]; i++) {
        const char *p = g_interesting_prefixes[i];
        size_t len = strlen(p);
        if (len > 8) len = 8;
        if (memcmp(prefix, p, len) == 0) return true;
    }
    return false;
}

// =========================================================================
// Level-2: maps cache
// =========================================================================
struct maps_entry {
    uint64_t start;
    uint64_t end;
    char name[256];
};

static std::vector<maps_entry> g_maps_cache;
static uint64_t g_maps_cache_time = 0;

static uint64_t now_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static bool ensure_dir_recursive(const std::string &dir) {
    if (dir.empty()) return true;

    size_t pos = (dir[0] == '/') ? 1 : 0;
    while (pos <= dir.size()) {
        size_t slash = dir.find('/', pos);
        std::string cur = (slash == std::string::npos) ? dir : dir.substr(0, slash);
        if (!cur.empty()) {
            if (mkdir(cur.c_str(), 0755) < 0 && errno != EEXIST) {
                return false;
            }
        }
        if (slash == std::string::npos) break;
        pos = slash + 1;
    }
    return true;
}

static void maybe_apply_so_hooks_fallback(pid_t pid, const char *reason, bool force) {
    if (g_all_so_hooks_done) return;

    uint64_t now = now_ms();
    if (!force && (now - g_last_so_hook_probe_ms) < 15) return;
    g_last_so_hook_probe_ms = now;

    for (size_t i = 0; i < g_so_hooks.size(); i++) {
        if (g_so_hooks[i].done) continue;
        if (find_so_load_bias_in_maps(pid, g_so_hooks[i].so_name.c_str()) == 0) continue;
        LOGI(TAG "so_hook: fallback trigger (%s), %s is in maps",
             reason, g_so_hooks[i].so_name.c_str());
        apply_so_hooks_via_ptrace(pid, i);
    }
}

static void refresh_maps_cache(pid_t pid) {
    uint64_t now = now_ms();
    if (!g_maps_cache.empty() && (now - g_maps_cache_time) < 1000) return;
    g_maps_cache.clear();
    g_maps_cache_time = now;

    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *fp = fopen(maps_path, "r");
    if (!fp) return;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        maps_entry e{};
        char perms[8];
        unsigned long offset, dev_major, dev_minor, inode;
        int n = sscanf(line, "%" PRIx64 "-%" PRIx64 " %4s %lx %lx:%lx %lu %255s",
                       &e.start, &e.end, perms, &offset,
                       &dev_major, &dev_minor, &inode, e.name);
        if (n >= 2) g_maps_cache.push_back(e);
    }
    fclose(fp);
}

static std::string resolve_caller_cached(pid_t pid, uint64_t pc) {
    refresh_maps_cache(pid);
    for (auto &e : g_maps_cache) {
        if (pc >= e.start && pc < e.end) {
            const char *basename = strrchr(e.name, '/');
            basename = basename ? basename + 1 : e.name;
            char buf[320];
            snprintf(buf, sizeof(buf), "%s+0x%" PRIx64, basename, pc - e.start);
            return buf;
        }
    }
    char buf[32];
    snprintf(buf, sizeof(buf), "0x%" PRIx64, pc);
    return buf;
}


// =========================================================================
// Level-3: fd cache for getdents64
// =========================================================================
static std::map<tracked_fd_key, std::string> g_fd_cache;

static const std::string& resolve_fd_cached(pid_t pid, uint64_t fd_val) {
    tracked_fd_key key = make_fd_key(pid, fd_val);
    auto it = g_fd_cache.find(key);
    if (it != g_fd_cache.end()) return it->second;

    char link_path[96];
    char target[256] = {0};
    pid_t proc_pid = (key.tgid > 0) ? key.tgid : pid;
    snprintf(link_path, sizeof(link_path), "/proc/%d/fd/%llu",
             proc_pid, (unsigned long long)fd_val);
    ssize_t len = readlink(link_path, target, sizeof(target) - 1);
    if (len <= 0 && proc_pid != pid) {
        // Fallback for rare cases where tgid resolution is stale.
        snprintf(link_path, sizeof(link_path), "/proc/%d/fd/%llu",
                 pid, (unsigned long long)fd_val);
        len = readlink(link_path, target, sizeof(target) - 1);
    }
    if (len > 0) target[len] = '\0';

    g_fd_cache[key] = target;
    return g_fd_cache[key];
}

static uint64_t g_fd_cache_time = 0;
static void maybe_flush_fd_cache() {
    uint64_t now = now_ms();
    if ((now - g_fd_cache_time) > 5000) {
        g_fd_cache.clear();
        g_fd_cache_time = now;
    }
}

// =========================================================================
// Read full string from tracee
// =========================================================================
static std::string read_tracee_string(pid_t pid, uint64_t addr, size_t max_len = 256) {
    std::string result;
    if (addr == 0) return "(null)";
    addr = untag_user_addr(addr);
    for (size_t off = 0; off < max_len; off += sizeof(long)) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid,
                           (void*)(addr + off), nullptr);
        if (errno != 0) { result += "<?>"; break; }
        const char *bytes = reinterpret_cast<const char*>(&word);
        for (size_t i = 0; i < sizeof(long); i++) {
            if (bytes[i] == '\0') return result;
            result += bytes[i];
        }
    }
    return result;
}

// =========================================================================
// Write bytes into tracee memory via PTRACE_POKEDATA
// =========================================================================
static bool write_tracee_mem(pid_t pid, uint64_t addr,
                             const void *data, size_t len) {
    addr = untag_user_addr(addr);
    const uint8_t *src = (const uint8_t*)data;
    size_t off = 0;
    while (off < len) {
        long word;
        if (off + sizeof(long) <= len) {
            memcpy(&word, src + off, sizeof(long));
        } else {
            // Partial word: read-modify-write
            errno = 0;
            word = ptrace(PTRACE_PEEKDATA, pid,
                          (void*)(addr + off), nullptr);
            if (errno != 0) return false;
            memcpy(&word, src + off, len - off);
        }
        if (ptrace(PTRACE_POKEDATA, pid,
                   (void*)(addr + off), (void*)word) < 0)
            return false;
        off += sizeof(long);
    }
    return true;
}

// =========================================================================
// Read bytes from tracee memory via PTRACE_PEEKDATA
// =========================================================================
static bool read_tracee_mem(pid_t pid, uint64_t addr,
                            void *out, size_t len) {
    addr = untag_user_addr(addr);
    uint8_t *dst = (uint8_t*)out;
    size_t off = 0;
    while (off < len) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid,
                           (void*)(addr + off), nullptr);
        if (errno != 0) return false;
        size_t chunk = (off + sizeof(long) <= len) ? sizeof(long) : (len - off);
        memcpy(dst + off, &word, chunk);
        off += sizeof(long);
    }
    return true;
}

// =========================================================================
// TracerPid tampering: scan buffer and replace TracerPid value with 0
// =========================================================================
// /proc/self/status format: "TracerPid:\t<number>\n"
// We replace the number with "0" and pad the rest with spaces until newline.
static bool tamper_tracer_pid(pid_t pid, uint64_t buf_addr, size_t buf_len) {
    if (buf_len == 0 || buf_len > 8192) return false;

    std::vector<char> buf(buf_len);
    if (!read_tracee_mem(pid, buf_addr, buf.data(), buf_len))
        return false;

    // Search for "TracerPid:\t"
    const char *needle = "TracerPid:\t";
    size_t needle_len = strlen(needle);
    char *pos = nullptr;
    for (size_t i = 0; i + needle_len <= buf_len; i++) {
        if (memcmp(buf.data() + i, needle, needle_len) == 0) {
            pos = buf.data() + i;
            break;
        }
    }
    if (!pos) return false;  // TracerPid line not in this read chunk

    // Found it. Replace the number after "TracerPid:\t" with "0"
    // and pad with spaces until the newline.
    char *num_start = pos + needle_len;
    char *buf_end = buf.data() + buf_len;

    // Find the newline
    char *nl = num_start;
    while (nl < buf_end && *nl != '\n') nl++;

    // Write "0" then spaces until newline
    if (num_start < buf_end) {
        *num_start = '0';
        for (char *p = num_start + 1; p < nl; p++)
            *p = ' ';
    }

    // Write the modified region back
    size_t mod_offset = (size_t)(num_start - buf.data());
    size_t mod_len = (size_t)(nl - num_start);
    if (mod_len > 0) {
        uint64_t write_addr = buf_addr + mod_offset;
        if (!write_tracee_mem(pid, write_addr, num_start, mod_len)) {
            LOGE(TAG "POKEDATA failed for TracerPid tamper: %s",
                 strerror(errno));
            return false;
        }
    }

    LOGI(TAG "TracerPid tampered for pid %d", pid);
    return true;
}

// =========================================================================
// Syscall name lookup
// =========================================================================
static const char* syscall_name(uint64_t nr) {
    switch (nr) {
        case __NR_openat:     return "openat";
        case __NR_faccessat:  return "faccessat";
#ifdef __NR_newfstatat
        case __NR_newfstatat: return "newfstatat";
#endif
        case __NR_readlinkat: return "readlinkat";
#ifdef __NR_statx
        case __NR_statx:      return "statx";
#endif
        case __NR_getdents64: return "getdents64";
        case __NR_read:       return "read";
#ifdef __NR_pread64
        case __NR_pread64:    return "pread64";
#endif
        case __NR_close:      return "close";
#ifdef __NR_mmap
        case __NR_mmap:       return "mmap";
#endif
#ifdef __NR_mprotect
        case __NR_mprotect:   return "mprotect";
#endif
        case __NR_exit_group: return "exit_group";
        case __NR_kill:       return "kill";
        case __NR_tgkill:     return "tgkill";
        default:              return "unknown";
    }
}

// =========================================================================
// Statistics
// =========================================================================
static uint64_t g_stat_total = 0;
static uint64_t g_stat_filtered = 0;
static uint64_t g_stat_logged = 0;
static uint64_t g_stat_tampered = 0;
static uint64_t g_stat_last_report = 0;

static void maybe_report_stats() {
    uint64_t now = now_ms();
    if ((now - g_stat_last_report) < 10000) return;
    g_stat_last_report = now;

    if (g_log_fp && g_stat_total > 0) {
        fprintf(g_log_fp,
                "--- stats: total=%llu filtered=%llu logged=%llu tampered=%llu (%.1f%% filtered) ---\n",
                (unsigned long long)g_stat_total,
                (unsigned long long)g_stat_filtered,
                (unsigned long long)g_stat_logged,
                (unsigned long long)g_stat_tampered,
                g_stat_total > 0 ? (100.0 * g_stat_filtered / g_stat_total) : 0.0);
        fflush(g_log_fp);
    }
    LOGI(TAG "stats: total=%llu filtered=%llu logged=%llu tampered=%llu",
         (unsigned long long)g_stat_total,
         (unsigned long long)g_stat_filtered,
         (unsigned long long)g_stat_logged,
         (unsigned long long)g_stat_tampered);
}

// =========================================================================
// Log a single syscall event
// =========================================================================
static void log_syscall(pid_t pid, const char *name,
                        const char *path, const char *caller) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    if (g_log_fp) {
        fprintf(g_log_fp, "[%ld.%03ld] pid=%d %s(\"%s\") from %s\n",
                ts.tv_sec, ts.tv_nsec / 1000000,
                pid, name, path, caller);
        static int flush_counter = 0;
        if (++flush_counter >= 16) {
            fflush(g_log_fp);
            flush_counter = 0;
        }
    }
}

// =========================================================================
// ARM64 stack backtrace via FP (x29) chain + PTRACE_PEEKDATA
// =========================================================================
// ARM64 ABI: each frame has [FP+0]=prev_FP, [FP+8]=return_addr (LR saved)
// We walk the chain to collect return addresses and resolve them via maps.
static void capture_backtrace(pid_t pid, const tracer_regs &regs,
                              int max_depth = 20) {
    refresh_maps_cache(pid);

    uint64_t pc = tracer_get_pc(regs);
    uint64_t lr = regs.regs[30];  // x30 = LR
    uint64_t fp = regs.regs[29];  // x29 = FP

    LOGE(TAG "BACKTRACE pid=%d >>>", pid);
    LOGE(TAG "  #00 PC 0x%" PRIx64 "  %s", pc, resolve_caller_cached(pid, pc).c_str());
    LOGE(TAG "  #01 LR 0x%" PRIx64 "  %s", lr, resolve_caller_cached(pid, lr).c_str());

    if (g_log_fp) {
        fprintf(g_log_fp, "[BACKTRACE] pid=%d\n", pid);
        fprintf(g_log_fp, "  #00 PC 0x%" PRIx64 "  %s\n", pc, resolve_caller_cached(pid, pc).c_str());
        fprintf(g_log_fp, "  #01 LR 0x%" PRIx64 "  %s\n", lr, resolve_caller_cached(pid, lr).c_str());
    }

    // Walk FP chain
    for (int i = 2; i < max_depth && fp != 0; i++) {
        uint64_t clean_fp = fp & 0x00FFFFFFFFFFFFFFULL;  // untag
        if (clean_fp < 0x1000 || (clean_fp & 7) != 0) break;  // invalid alignment

        // Read [FP+0] = prev_fp, [FP+8] = return_addr
        errno = 0;
        long prev_fp_lo = ptrace(PTRACE_PEEKDATA, pid, (void *)clean_fp, nullptr);
        if (errno != 0) break;
        errno = 0;
        long ret_addr_lo = ptrace(PTRACE_PEEKDATA, pid, (void *)(clean_fp + 8), nullptr);
        if (errno != 0) break;

        uint64_t prev_fp = (uint64_t)prev_fp_lo;
        uint64_t ret_addr = (uint64_t)ret_addr_lo;

        if (ret_addr == 0) break;

        std::string sym = resolve_caller_cached(pid, ret_addr);
        LOGE(TAG "  #%02d RA 0x%" PRIx64 "  %s", i, ret_addr, sym.c_str());
        if (g_log_fp) {
            fprintf(g_log_fp, "  #%02d RA 0x%" PRIx64 "  %s\n", i, ret_addr, sym.c_str());
        }

        // Detect loops or upward-growing stack (corruption)
        if (prev_fp <= clean_fp && prev_fp != 0) break;
        fp = prev_fp;
    }

    LOGE(TAG "BACKTRACE <<<");
    if (g_log_fp) {
        fprintf(g_log_fp, "[BACKTRACE] end\n");
        fflush(g_log_fp);
    }
}

// =========================================================================
// Public API
// =========================================================================

void syscall_handler_init(pid_t target_pid, const std::string &log_path, bool verbose_logs,
                          bool block_self_kill,
                          const std::vector<so_hook_config> &so_hooks) {
    g_target_pid = target_pid;
    g_verbose_logs = verbose_logs;
    g_block_self_kill = block_self_kill;
    g_maps_stage_start_ms = now_ms();
    g_stat_total = g_stat_filtered = g_stat_logged = g_stat_tampered = 0;
    g_stat_last_report = now_ms();
    g_fd_cache_time = now_ms();
    g_tid_to_tgid_cache.clear();
    g_status_fds.clear();
    g_maps_fds.clear();
    g_maps_fd_states.clear();
    g_waiting_read_exit.clear();
    g_pending_exit.clear();

    // SO load-time hooks
    g_so_hooks.clear();
    g_so_hook_fds.clear();
    g_so_hook_fds_raw.clear();
    g_all_so_hooks_done = so_hooks.empty();
    g_last_so_hook_probe_ms = 0;
    for (auto &shc : so_hooks) {
        so_hook_state state;
        state.so_name = shc.so_name;
        state.hooks = shc.hooks;
        state.done = false;
        g_so_hooks.push_back(std::move(state));
        LOGI(TAG "so_hook: watching for %s (%zu hooks)", shc.so_name.c_str(), shc.hooks.size());
    }

    // Default protected libraries for ELF checksum bypass.
    // These are the libraries that DetectFrida checks via memdisk compare.
    // TODO: make this configurable via config.json in the future.
    g_protected_libs.clear();
    g_protected_libs.push_back("libc.so");
    g_protected_libs.push_back("libnative-lib.so");

    if (!log_path.empty()) {
        // Ensure parent directory exists (tracer runs as root)
        size_t slash = log_path.rfind('/');
        if (slash != std::string::npos) {
            std::string dir = log_path.substr(0, slash);
            if (!dir.empty() && !ensure_dir_recursive(dir)) {
                LOGE(TAG "failed to create log dir %s: %s",
                     dir.c_str(), strerror(errno));
            }
        }
        g_log_fp = fopen(log_path.c_str(), "a");
        if (!g_log_fp) {
            LOGE(TAG "failed to open log %s: %s",
                 log_path.c_str(), strerror(errno));
        } else {
            fprintf(g_log_fp, "=== tracer started, target pid=%d, block_self_kill=%d ===\n",
                    target_pid, g_block_self_kill ? 1 : 0);
            fflush(g_log_fp);
        }
    }
}

seccomp_action handle_seccomp_stop(pid_t pid) {
    g_stat_total++;

    tracer_regs regs;
    if (!tracer_getregs(pid, regs)) {
        LOGE(TAG "GETREGSET failed for pid %d: %s", pid, strerror(errno));
        return SECCOMP_ACT_CONTINUE;
    }

    uint64_t nr = tracer_get_syscall_nr(regs);

    // Fallback path for ROMs where linker does not close the SO fd.
    maybe_apply_so_hooks_fallback(pid, "seccomp-stop", false);

    // ---- Intercept process-killing syscalls: always log + backtrace ----
    if (nr == __NR_exit_group || nr == __NR_kill || nr == __NR_tgkill) {
        uint64_t pc = tracer_get_pc(regs);
        std::string caller = resolve_caller_cached(pid, pc);
        const char *action = g_block_self_kill ? "BLOCKED" : "DETECTED";

        if (nr == __NR_exit_group) {
            uint64_t exit_code = tracer_get_arg(regs, 0);
            LOGE(TAG "%s exit_group(%llu) from pid=%d PC=0x%" PRIx64 " caller=%s",
                 action, (unsigned long long)exit_code, pid, pc, caller.c_str());
        } else if (nr == __NR_kill) {
            uint64_t target_pid_arg = tracer_get_arg(regs, 0);
            uint64_t sig = tracer_get_arg(regs, 1);
            LOGE(TAG "%s kill(pid=%llu, sig=%llu) from pid=%d PC=0x%" PRIx64 " caller=%s",
                 action, (unsigned long long)target_pid_arg, (unsigned long long)sig,
                 pid, pc, caller.c_str());
        } else {
            uint64_t tgid_arg = tracer_get_arg(regs, 0);
            uint64_t tid_arg = tracer_get_arg(regs, 1);
            uint64_t sig = tracer_get_arg(regs, 2);
            LOGE(TAG "%s tgkill(tgid=%llu, tid=%llu, sig=%llu) from pid=%d PC=0x%" PRIx64 " caller=%s",
                 action, (unsigned long long)tgid_arg, (unsigned long long)tid_arg,
                 (unsigned long long)sig, pid, pc, caller.c_str());
        }

        if (g_log_fp) {
            fprintf(g_log_fp, "[KILL_INTERCEPT] %s nr=%s pid=%d PC=0x%" PRIx64 " caller=%s args=[%llu,%llu,%llu]\n",
                    action, syscall_name(nr), pid, pc, caller.c_str(),
                    (unsigned long long)tracer_get_arg(regs, 0),
                    (unsigned long long)tracer_get_arg(regs, 1),
                    (unsigned long long)tracer_get_arg(regs, 2));
            fflush(g_log_fp);
        }

        // Capture full stack backtrace for caller analysis
        capture_backtrace(pid, regs);

        if (g_block_self_kill) {
            // Block the syscall by replacing nr with -1 (returns -ENOSYS)
            tracer_set_syscall_nr(regs, (uint64_t)-1);
            tracer_setregs(pid, regs);
        }
        // When not blocking, syscall proceeds normally after PTRACE_CONT
        return SECCOMP_ACT_CONTINUE;
    }

    // For SO load-time hooks, wait mmap-exit when mmap(fd) uses a tracked so fd.
#ifdef __NR_mmap
    if (nr == __NR_mmap && !g_all_so_hooks_done) {
        uint64_t fd_val = tracer_get_arg(regs, 4);
        if (fd_val != (uint64_t)-1 && resolve_tracee_tgid(pid) == g_target_pid) {
            if (lookup_so_hook_idx_by_fd(pid, fd_val, nullptr)) {
                LOGI(TAG "so_hook: mmap(fd=%llu) pid=%d hit tracked so fd -> WAIT_EXIT",
                     (unsigned long long)fd_val, pid);
            } else {
                const std::string &fd_path = resolve_fd_cached(pid, fd_val);
                size_t idx = 0;
                if (match_pending_so_hook_by_path(fd_path, &idx)) {
                    tracked_fd_key key = make_fd_key(pid, fd_val);
                    g_so_hook_fds[key] = idx;
                    g_so_hook_fds_raw[fd_val] = idx;
                    LOGI(TAG "so_hook: mmap(fd=%llu) resolved via fd-path=%s -> idx=%zu",
                         (unsigned long long)fd_val, fd_path.c_str(), idx);
                } else if (g_verbose_logs) {
                    LOGI(TAG "so_hook: mmap(fd=%llu) pid=%d path=%s not target, but WAIT_EXIT for verification",
                         (unsigned long long)fd_val, pid, fd_path.c_str());
                }
            }
            g_waiting_read_exit.insert(pid);
            remember_pending_exit(pid, regs);
            return SECCOMP_ACT_WAIT_EXIT;
        }
    }
#endif
#ifdef __NR_mprotect
    if (nr == __NR_mprotect && !g_all_so_hooks_done &&
        resolve_tracee_tgid(pid) == g_target_pid) {
        g_waiting_read_exit.insert(pid);
        remember_pending_exit(pid, regs);
        return SECCOMP_ACT_WAIT_EXIT;
    }
#endif

    // close() cleanup for tracked fds (maps/status) and SO hook fds.
    if (nr == __NR_close) {
        uint64_t fd_val = tracer_get_arg(regs, 0);
        tracked_fd_key key = make_fd_key(pid, fd_val);
        bool is_maps = g_maps_fds.count(key) > 0;
        bool is_status = g_status_fds.count(key) > 0;
        bool is_so_hook = lookup_so_hook_idx_by_fd(pid, fd_val, nullptr);
        if (is_maps || is_status || is_so_hook) {
            LOGI(TAG "close(fd=%llu) pid=%d: maps=%d status=%d so_hook=%d -> WAIT_EXIT",
                 (unsigned long long)fd_val, pid, is_maps, is_status, is_so_hook);
            g_waiting_read_exit.insert(pid);
            remember_pending_exit(pid, regs);
            return SECCOMP_ACT_WAIT_EXIT;
        }
        // close() on non-tracked fd: keep fast path.
        g_fd_cache.erase(key);
        g_stat_filtered++;
        maybe_report_stats();
        return SECCOMP_ACT_CONTINUE;
    }

    // --- For openat: check if it opens maps/status files we may tamper ---
    if (nr == __NR_openat) {
        uint64_t path_addr = tracer_get_arg(regs, 1);

        // SO load-time hook: check if this openat is for a target SO.
        // We need WAIT_EXIT to get the fd and track it for close().
        if (!g_all_so_hooks_done) {
            std::string path = read_tracee_string(pid, path_addr);
            std::string basename = normalize_path_basename(path);
            for (size_t i = 0; i < g_so_hooks.size(); i++) {
                if (!g_so_hooks[i].done && g_so_hooks[i].so_name == basename) {
                    LOGI(TAG "so_hook: intercepted openat(%s)", path.c_str());
                    g_waiting_read_exit.insert(pid);
                    remember_pending_exit(pid, regs);
                    return SECCOMP_ACT_WAIT_EXIT;
                }
            }
        }

        char prefix[8] = {0};
        bool have_prefix = peek_prefix(pid, path_addr, prefix);

        bool maybe_interesting = have_prefix && is_interesting_prefix(prefix);

        if (maybe_interesting) {
            std::string path = read_tracee_string(pid, path_addr);

            // Check /proc/self/maps for checksum bypass
            if (is_proc_maps_path(path) && !g_protected_libs.empty()) {
                g_waiting_read_exit.insert(pid);
                remember_pending_exit(pid, regs);
                uint64_t pc = tracer_get_pc(regs);
                std::string caller = resolve_caller_cached(pid, pc);
                log_syscall(pid, "openat", path.c_str(), caller.c_str());
                g_stat_logged++;
                if (g_verbose_logs && g_log_fp) {
                    fprintf(g_log_fp,
                            "[maps_bypass] detected openat on %s\n",
                            path.c_str());
                    fflush(g_log_fp);
                }
                return SECCOMP_ACT_WAIT_EXIT;
            }

            // Check /proc/self/status for TracerPid hiding
            if (is_proc_status_path(path)) {
                g_waiting_read_exit.insert(pid);
                remember_pending_exit(pid, regs);
                uint64_t pc = tracer_get_pc(regs);
                std::string caller = resolve_caller_cached(pid, pc);
                log_syscall(pid, "openat", path.c_str(), caller.c_str());
                g_stat_logged++;
                return SECCOMP_ACT_WAIT_EXIT;
            }

            // Interesting path but not maps/status — log normally
            uint64_t pc = tracer_get_pc(regs);
            std::string caller = resolve_caller_cached(pid, pc);
            log_syscall(pid, syscall_name(nr), path.c_str(), caller.c_str());
            g_stat_logged++;
            maybe_report_stats();
            return SECCOMP_ACT_CONTINUE;
        }
        g_stat_filtered++;
        maybe_report_stats();
        return SECCOMP_ACT_CONTINUE;
    }
    if (nr == __NR_read
#ifdef __NR_pread64
        || nr == __NR_pread64
#endif
    ) {
        uint64_t fd_val = tracer_get_arg(regs, 0);
        tracked_fd_key key = make_fd_key(pid, fd_val);
        if (!g_maps_fds.count(key) && !g_status_fds.count(key)) {
            // Recovery path: if openat-exit tracking missed this fd, detect maps/status
            // directly from /proc/<tid>/fd/<fd> and add it lazily.
            const std::string &fd_path = resolve_fd_cached(pid, fd_val);
            if (is_proc_maps_path(fd_path) && !g_protected_libs.empty()) {
                g_maps_fds.insert(key);
                auto it = g_maps_fd_states.find(key);
                if (it == g_maps_fd_states.end()) {
                    maps_fd_state state{};
                    uint64_t age_ms = now_ms() - g_maps_stage_start_ms;
                    state.tamper_enabled = (key.tgid != g_target_pid) || (age_ms > 1500);
                    if (state.tamper_enabled) {
                        build_sanitized_maps_snapshot(g_target_pid, state.sanitized_maps);
                    }
                    g_maps_fd_states[key] = std::move(state);
                }
                if (g_verbose_logs && g_log_fp) {
                    fprintf(g_log_fp,
                            "[maps_bypass] late-track maps fd: tid=%d tgid=%d fd=%llu path=%s\n",
                            pid, key.tgid, (unsigned long long)fd_val, fd_path.c_str());
                }
            } else if (is_proc_status_path(fd_path)) {
                g_status_fds.insert(key);
                if (g_verbose_logs && g_log_fp) {
                    fprintf(g_log_fp,
                            "[tamper] late-track status fd: tid=%d tgid=%d fd=%llu path=%s\n",
                            pid, key.tgid, (unsigned long long)fd_val, fd_path.c_str());
                }
            }
        }

        // Check maps fds first (checksum bypass)
        if (g_maps_fds.count(key)) {
            if (g_verbose_logs && g_log_fp) {
                fprintf(g_log_fp,
                        "[maps_bypass] read wait: tid=%d tgid=%d fd=%llu\n",
                        pid, key.tgid, (unsigned long long)fd_val);
                fflush(g_log_fp);
            }
            g_waiting_read_exit.insert(pid);
            remember_pending_exit(pid, regs);
            return SECCOMP_ACT_WAIT_EXIT;
        }
        // Then check status fds (TracerPid bypass)
        if (g_status_fds.count(key)) {
            g_waiting_read_exit.insert(pid);
            remember_pending_exit(pid, regs);
            return SECCOMP_ACT_WAIT_EXIT;
        }
        // read() on non-tracked fd: skip entirely
        g_stat_filtered++;
        maybe_report_stats();
        return SECCOMP_ACT_CONTINUE;
    }

    // --- Level-1 filter ---
    // getdents64 is fd-based; mmap/mprotect are non-path syscalls.
    if (nr == __NR_getdents64) {
        maybe_flush_fd_cache();
        uint64_t fd_val = tracer_get_arg(regs, 0);
        const std::string &fd_path = resolve_fd_cached(pid, fd_val);
        if (fd_path.find("/proc/") == std::string::npos) {
            g_stat_filtered++;
            maybe_report_stats();
            return SECCOMP_ACT_CONTINUE;
        }
    }
#ifdef __NR_mmap
    else if (nr == __NR_mmap) {
        // No prefix filtering: mmap args are addr/len/prot/flags/fd/off.
    }
#endif
#ifdef __NR_mprotect
    else if (nr == __NR_mprotect) {
        // No prefix filtering: mprotect args are addr/len/prot.
    }
#endif
    else {
        uint64_t path_addr = tracer_get_arg(regs, 1);
        char prefix[8] = {0};
        if (peek_prefix(pid, path_addr, prefix)) {
            if (!is_interesting_prefix(prefix)) {
                g_stat_filtered++;
                maybe_report_stats();
                return SECCOMP_ACT_CONTINUE;
            }
        }
    }

    // --- Level-2: full path + caller ---
    uint64_t pc = tracer_get_pc(regs);
    std::string caller = resolve_caller_cached(pid, pc);

    if (nr == __NR_getdents64) {
        uint64_t fd_val = tracer_get_arg(regs, 0);
        const std::string &fd_path = resolve_fd_cached(pid, fd_val);
        log_syscall(pid, "getdents64", fd_path.c_str(), caller.c_str());
#ifdef __NR_mmap
    } else if (nr == __NR_mmap) {
        uint64_t fd_val = tracer_get_arg(regs, 4);
        uint64_t prot = tracer_get_arg(regs, 2);
        uint64_t off = tracer_get_arg(regs, 5);
        char mmap_desc[192];
        if (fd_val != (uint64_t)-1) {
            const std::string &fd_path = resolve_fd_cached(pid, fd_val);
            snprintf(mmap_desc, sizeof(mmap_desc),
                     "fd=%lld prot=0x%llx off=0x%llx path=%s",
                     (long long)fd_val,
                     (unsigned long long)prot,
                     (unsigned long long)off,
                     fd_path.c_str());
        } else {
            snprintf(mmap_desc, sizeof(mmap_desc),
                     "fd=%lld prot=0x%llx off=0x%llx",
                     (long long)((int64_t)fd_val),
                     (unsigned long long)prot,
                     (unsigned long long)off);
        }
        log_syscall(pid, "mmap", mmap_desc, caller.c_str());
#endif
#ifdef __NR_mprotect
    } else if (nr == __NR_mprotect) {
        uint64_t addr = tracer_get_arg(regs, 0);
        uint64_t len = tracer_get_arg(regs, 1);
        uint64_t prot = tracer_get_arg(regs, 2);
        char mp_desc[128];
        snprintf(mp_desc, sizeof(mp_desc), "addr=0x%llx len=0x%llx prot=0x%llx",
                 (unsigned long long)addr,
                 (unsigned long long)len,
                 (unsigned long long)prot);
        log_syscall(pid, "mprotect", mp_desc, caller.c_str());
#endif
    } else {
        uint64_t path_addr = tracer_get_arg(regs, 1);
        std::string path = read_tracee_string(pid, path_addr);
        log_syscall(pid, syscall_name(nr), path.c_str(), caller.c_str());
    }

    g_stat_logged++;
    maybe_report_stats();
    return SECCOMP_ACT_CONTINUE;
}

void handle_syscall_exit(pid_t pid) {
    pending_exit_state pending{};
    bool have_pending = false;
    auto pending_it = g_pending_exit.find(pid);
    if (pending_it != g_pending_exit.end()) {
        pending = pending_it->second;
        g_pending_exit.erase(pending_it);
        have_pending = true;
    }

    tracer_regs regs;
    if (!tracer_getregs(pid, regs)) {
        LOGE(TAG "GETREGSET failed on exit for pid %d", pid);
        g_waiting_read_exit.erase(pid);
        return;
    }

    uint64_t nr = have_pending ? pending.nr : tracer_get_syscall_nr(regs);
    int64_t ret = (int64_t)tracer_get_retval(regs);

    if (nr == __NR_close) {
        uint64_t fd_val = have_pending ? pending.args[0] : tracer_get_arg(regs, 0);
        tracked_fd_key key = make_fd_key(pid, fd_val);
        size_t so_idx = 0;
        bool have_so_idx = lookup_so_hook_idx_by_fd(pid, fd_val, &so_idx);

        LOGI(TAG "close-exit: pid=%d fd=%llu ret=%lld so_hook_fds_count=%zu",
             pid, (unsigned long long)fd_val, (long long)ret,
             g_so_hook_fds.size() + g_so_hook_fds_raw.size());

        // SO load-time hook: apply patches when target SO's fd is closed
        // At this point the SO is mmap'd but .init_array hasn't run yet
        if (have_so_idx) {
            LOGI(TAG "so_hook: close(fd=%llu) matched hook_idx=%zu, ret=%lld, done=%d",
                 (unsigned long long)fd_val, so_idx, (long long)ret,
                 (so_idx < g_so_hooks.size()) ? g_so_hooks[so_idx].done : -1);
            if (ret == 0 && so_idx < g_so_hooks.size() && !g_so_hooks[so_idx].done) {
                apply_so_hooks_via_ptrace(pid, so_idx);
            }
            if (ret == 0) erase_so_hook_fd_tracking(pid, fd_val);
        } else {
            LOGI(TAG "close-exit: fd=%llu NOT in tracked so fds (tgid=%d)",
                 (unsigned long long)fd_val, key.tgid);
            // Dump all tracked so_hook_fds for debugging
            for (auto &entry : g_so_hook_fds) {
                LOGI(TAG "  g_so_hook_fds entry: tgid=%d fd=%llu -> idx=%zu",
                     entry.first.tgid, (unsigned long long)entry.first.fd, entry.second);
            }
            for (auto &entry : g_so_hook_fds_raw) {
                LOGI(TAG "  g_so_hook_fds_raw entry: fd=%llu -> idx=%zu",
                     (unsigned long long)entry.first, entry.second);
            }
        }

        if (ret == 0) {
            g_maps_fds.erase(key);
            g_maps_fd_states.erase(key);
            g_status_fds.erase(key);
        }
        g_fd_cache.erase(key);
    } else if (nr == __NR_openat) {
        if (ret >= 0) {
            // Resolve what path was opened via /proc/<pid>/fd/<fd>
            uint64_t opened_fd = (uint64_t)ret;
            tracked_fd_key open_key = make_fd_key(pid, opened_fd);
            pid_t proc_pid = (open_key.tgid > 0) ? open_key.tgid : pid;
            char link_path[96], target[256] = {0};
            snprintf(link_path, sizeof(link_path), "/proc/%d/fd/%lld",
                     proc_pid, (long long)ret);
            ssize_t len = readlink(link_path, target, sizeof(target) - 1);
            if (len <= 0 && proc_pid != pid) {
                snprintf(link_path, sizeof(link_path), "/proc/%d/fd/%lld",
                         pid, (long long)ret);
                len = readlink(link_path, target, sizeof(target) - 1);
            }
            std::string path_str;
            if (len > 0) {
                target[len] = '\0';
                path_str = target;
            } else if (have_pending) {
                // readlink may fail on some tid paths; fall back to original openat arg.
                path_str = read_tracee_string(pid, pending.args[1]);
            }

            if (!path_str.empty() && path_str != "<?>") {
                // SO load-time hook: track fd for target SOs
                if (!g_all_so_hooks_done) {
                    std::string basename = normalize_path_basename(path_str);
                    for (size_t i = 0; i < g_so_hooks.size(); i++) {
                        if (!g_so_hooks[i].done && g_so_hooks[i].so_name == basename) {
                            uint64_t fd_val = (uint64_t)ret;
                            tracked_fd_key key = make_fd_key(pid, fd_val);
                            g_so_hook_fds[key] = i;
                            g_so_hook_fds_raw[fd_val] = i;
                            LOGI(TAG "so_hook: openat(%s) -> fd=%lld, tracking for close() [pid=%d tgid=%d]",
                                 path_str.c_str(), (long long)ret, pid, key.tgid);
                            break;
                        }
                    }
                    maybe_apply_so_hooks_fallback(pid, "openat-exit", true);
                }

                if (is_proc_maps_path(path_str)) {
                    uint64_t fd_val = (uint64_t)ret;
                    tracked_fd_key key = make_fd_key(pid, fd_val);
                    g_maps_fds.insert(key);
                    g_fd_cache.erase(key);

                    maps_fd_state state{};
                    // Avoid breaking constructor-time bootstrap that parses
                    // executable mappings before checksums are captured.
                    uint64_t age_ms = now_ms() - g_maps_stage_start_ms;
                    state.tamper_enabled = (key.tgid != g_target_pid) || (age_ms > 1500);
                    if (state.tamper_enabled) {
                        if (!build_sanitized_maps_snapshot(g_target_pid, state.sanitized_maps)) {
                            LOGW(TAG "maps_bypass: failed to prebuild sanitized snapshot for pid %d",
                                 g_target_pid);
                        }
                    }
                    g_maps_fd_states[key] = std::move(state);

                    if (g_verbose_logs) {
                        LOGI(TAG "maps_bypass: tracking maps fd=%lld for pid %d",
                             (long long)ret, pid);
                    }
                    if (g_verbose_logs && g_log_fp) {
                        fprintf(g_log_fp,
                                "[maps_bypass] tracking maps fd=%lld -> %s (enabled=%d)\n",
                                (long long)ret, path_str.c_str(),
                                g_maps_fd_states[key].tamper_enabled ? 1 : 0);
                        fflush(g_log_fp);
                    }
                } else if (is_proc_status_path(path_str)) {
                    tracked_fd_key key = make_fd_key(pid, (uint64_t)ret);
                    g_status_fds.insert(key);
                    if (g_verbose_logs) {
                        LOGI(TAG "tracking status fd=%lld for pid %d",
                             (long long)ret, pid);
                    }
                }
            } else {
                // Final fallback: keep status tracking behavior for legacy logic.
                tracked_fd_key key = make_fd_key(pid, (uint64_t)ret);
                g_status_fds.insert(key);
                if (g_verbose_logs) {
                    LOGI(TAG "tracking status fd=%lld for pid %d (fallback)",
                         (long long)ret, pid);
                }
            }
        }
    }
#ifdef __NR_mmap
    else if (nr == __NR_mmap) {
        if (!g_all_so_hooks_done && ret > 0) {
            uint64_t fd_val = have_pending ? pending.args[4] : tracer_get_arg(regs, 4);
            size_t idx = 0;
            bool matched = false;
            std::string fd_path;
            if (lookup_so_hook_idx_by_fd(pid, fd_val, &idx)) {
                matched = true;
            } else if (fd_val != (uint64_t)-1) {
                fd_path = resolve_fd_cached(pid, fd_val);
                if (match_pending_so_hook_by_path(fd_path, &idx)) {
                    matched = true;
                    tracked_fd_key key = make_fd_key(pid, fd_val);
                    g_so_hook_fds[key] = idx;
                    g_so_hook_fds_raw[fd_val] = idx;
                }
            }
            if (matched) {
                uint64_t prot = have_pending ? pending.args[2] : tracer_get_arg(regs, 2);
                uint64_t map_off = have_pending ? pending.args[5] : tracer_get_arg(regs, 5);
                uintptr_t map_addr = (uintptr_t)ret;
                uintptr_t load_bias = map_addr - (uintptr_t)map_off;

                LOGI(TAG "so_hook: mmap-exit fd=%llu addr=0x%" PRIxPTR
                         " off=0x%" PRIx64 " prot=0x%" PRIx64 " path=%s -> load_bias=0x%" PRIxPTR,
                     (unsigned long long)fd_val, map_addr, map_off, prot,
                     fd_path.empty() ? "?" : fd_path.c_str(), load_bias);

                if ((prot & PROT_EXEC) != 0) {
                    bool patched = (idx < g_so_hooks.size()) &&
                                   apply_so_hooks_at_load_bias(pid, idx, load_bias, "mmap-exec");
                    if (patched) {
                        erase_so_hook_fd_tracking(pid, fd_val);
                    }
                }
            } else if (g_verbose_logs && fd_val != (uint64_t)-1 &&
                       resolve_tracee_tgid(pid) == g_target_pid) {
                const std::string &unmatched_path = resolve_fd_cached(pid, fd_val);
                LOGI(TAG "so_hook: mmap-exit fd=%llu path=%s not matched",
                     (unsigned long long)fd_val, unmatched_path.c_str());
            }
        }
        if (!g_all_so_hooks_done) {
            maybe_apply_so_hooks_fallback(pid, "mmap-exit", true);
        }
    }
#endif
#ifdef __NR_mprotect
    else if (nr == __NR_mprotect) {
        if (!g_all_so_hooks_done && ret == 0 && resolve_tracee_tgid(pid) == g_target_pid) {
            uint64_t addr = have_pending ? pending.args[0] : tracer_get_arg(regs, 0);
            uint64_t len = have_pending ? pending.args[1] : tracer_get_arg(regs, 1);
            uint64_t prot = have_pending ? pending.args[2] : tracer_get_arg(regs, 2);
            if ((prot & PROT_EXEC) != 0) {
                LOGI(TAG "so_hook: mprotect-exit addr=0x%" PRIx64
                         " len=0x%" PRIx64 " prot=0x%" PRIx64 " -> try patch",
                     addr, len, prot);
                maybe_apply_so_hooks_fallback(pid, "mprotect-exit", true);
            }
        }
    }
#endif
    else if (nr == __NR_read
#ifdef __NR_pread64
               || nr == __NR_pread64
#endif
    ) {
        if (g_verbose_logs && g_log_fp) {
            uint64_t fd_val = have_pending ? pending.args[0] : tracer_get_arg(regs, 0);
            tracked_fd_key key = make_fd_key(pid, fd_val);
            int maps_enabled = -1;
            auto st_it = g_maps_fd_states.find(key);
            if (st_it != g_maps_fd_states.end()) {
                maps_enabled = st_it->second.tamper_enabled ? 1 : 0;
            }
            fprintf(g_log_fp,
                    "[maps_bypass] read-exit: tid=%d tgid=%d fd=%llu ret=%lld tracked_maps=%d tracked_status=%d pending=%d maps_enabled=%d\n",
                    pid, key.tgid, (unsigned long long)fd_val, (long long)ret,
                    g_maps_fds.count(key) ? 1 : 0,
                    g_status_fds.count(key) ? 1 : 0,
                    have_pending ? 1 : 0,
                    maps_enabled);
            fflush(g_log_fp);
        }
        if (ret > 0) {
            uint64_t fd_val = have_pending ? pending.args[0] : tracer_get_arg(regs, 0);
            uint64_t buf_addr = have_pending ? pending.args[1] : tracer_get_arg(regs, 1);
            tracked_fd_key key = make_fd_key(pid, fd_val);

            // Check maps fd first (checksum bypass via maps tampering)
            if (g_maps_fds.count(key)) {
                bool tampered = tamper_maps_read_stream(pid, fd_val, buf_addr, (size_t)ret);
                if (tampered) {
                    g_stat_tampered++;
                    if (g_verbose_logs && g_log_fp) {
                        fprintf(g_log_fp,
                                "[maps_bypass] tampered read() on maps fd=%llu, "
                                "%lld bytes\n",
                                (unsigned long long)fd_val, (long long)ret);
                        fflush(g_log_fp);
                    }
                } else if (g_verbose_logs && g_log_fp) {
                    fprintf(g_log_fp,
                            "[maps_bypass] read seen but unchanged: tid=%d tgid=%d fd=%llu bytes=%lld\n",
                            pid, key.tgid, (unsigned long long)fd_val, (long long)ret);
                    fflush(g_log_fp);
                }
            } else if (g_status_fds.count(key)) {
                // TracerPid tampering
                if (tamper_tracer_pid(pid, buf_addr, (size_t)ret)) {
                    g_stat_tampered++;
                    if (g_log_fp) {
                        fprintf(g_log_fp,
                                "[tamper] pid=%d read() on status fd, "
                                "replaced TracerPid, %lld bytes\n",
                                pid, (long long)ret);
                        fflush(g_log_fp);
                    }
                }
            }
        }
    }

    g_waiting_read_exit.erase(pid);
}

void handle_fatal_signal(pid_t pid, int sig, const tracer_regs &regs) {
    uint64_t pc = tracer_get_pc(regs);
    std::string caller = resolve_caller_cached(pid, pc);

    LOGE(TAG "FATAL_SIGNAL: pid=%d sig=%d (%s) PC=0x%" PRIx64 " caller=%s",
         pid, sig, strsignal(sig), pc, caller.c_str());

    if (g_log_fp) {
        fprintf(g_log_fp,
                "[FATAL_SIGNAL] pid=%d sig=%d (%s) PC=0x%" PRIx64 " caller=%s\n",
                pid, sig, strsignal(sig), pc, caller.c_str());
        fflush(g_log_fp);
    }

    // Capture full stack backtrace
    capture_backtrace(pid, regs);
}

void syscall_handler_fini() {
    if (g_log_fp) {
        fprintf(g_log_fp,
                "=== tracer finished: total=%llu filtered=%llu "
                "logged=%llu tampered=%llu maps_fds_tracked=%zu ===\n",
                (unsigned long long)g_stat_total,
                (unsigned long long)g_stat_filtered,
                (unsigned long long)g_stat_logged,
                (unsigned long long)g_stat_tampered,
                g_maps_fds.size());
        fclose(g_log_fp);
        g_log_fp = nullptr;
    }
    g_maps_fds.clear();
    g_maps_fd_states.clear();
    g_status_fds.clear();
    g_tid_to_tgid_cache.clear();
    g_pending_exit.clear();
    g_protected_libs.clear();
    g_so_hooks.clear();
    g_so_hook_fds.clear();
    g_so_hook_fds_raw.clear();
    g_last_so_hook_probe_ms = 0;
}
