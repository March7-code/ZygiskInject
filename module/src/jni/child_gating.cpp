#include "child_gating.h"

#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <log.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>
#include <future>
#include <string>
#include <vector>

#include "config.h"
#include "inject.h"

static std::string child_gating_mode;  // NOLINT
static std::vector<std::string> injected_libraries;

// Real libc fork/vfork resolved via dlsym.
static pid_t (*real_fork)() = nullptr;
static pid_t (*real_vfork)() = nullptr;

// Saved GOT slots so we can restore later if needed.
static std::vector<void **> g_fork_got_slots;
static std::vector<void **> g_vfork_got_slots;

static pid_t fork_replacement() {
    pid_t parent_pid = getpid();
    LOGI("[child_gating][pid %d] detected fork/vfork", parent_pid);

    pid_t child_pid = real_fork();
    if (child_pid != 0) {
        LOGI("[child_gating][pid %d] returning from forking %d", parent_pid, child_pid);
        return child_pid;
    }

    child_pid = getpid();

    auto logContext = "[child_gating][pid " + std::to_string(child_pid) + "] ";

    if (child_gating_mode == "kill") {
        LOGI("%skilling child process", logContext.c_str());
        exit(0);
    }

    if (child_gating_mode == "freeze") {
        LOGI("%sfreezing child process", logContext.c_str());
        std::promise<void>().get_future().wait();
        return 0;
    }

    if (child_gating_mode != "inject") {
        LOGI("%sunknown child_gating_mode %s", logContext.c_str(), child_gating_mode.c_str());
        return 0;
    }

    for (auto &lib_path : injected_libraries) {
        LOGI("%sInjecting %s", logContext.c_str(), lib_path.c_str());
        inject_lib(lib_path, logContext);
    }

    return 0;
}

// ---------------------------------------------------------------------------
// GOT patching helpers (same approach as inject.cpp, no .text modification)
// ---------------------------------------------------------------------------

static void *patch_got_slot_cg(void *got_addr, void *new_func) {
    uintptr_t page = (uintptr_t)got_addr & ~(uintptr_t)(getpagesize() - 1);
    size_t page_size = (size_t)getpagesize();

    mprotect((void *)page, page_size, PROT_READ | PROT_WRITE);
    void *old = *(void **)got_addr;
    *(void **)got_addr = new_func;
    mprotect((void *)page, page_size, PROT_READ);

    return old;
}

// Walk ELF dynamic section and patch GOT entries for `sym_name`.
static void patch_got_for_sym(uintptr_t base, const char *sym_name,
                              void *target_func, void *hook_func,
                              std::vector<void **> &out_slots) {
    auto *ehdr = reinterpret_cast<ElfW(Ehdr) *>(base);
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) return;

    auto *phdr = reinterpret_cast<ElfW(Phdr) *>(base + ehdr->e_phoff);

    ElfW(Dyn) *dyn_start = nullptr;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dyn_start = reinterpret_cast<ElfW(Dyn) *>(base + phdr[i].p_offset);
            break;
        }
    }
    if (!dyn_start) return;

    uintptr_t jmprel = 0, rela = 0;
    size_t jmprel_sz = 0, rela_sz = 0, rela_ent = 0;
    uintptr_t symtab_addr = 0, strtab_addr = 0;

    for (ElfW(Dyn) *d = dyn_start; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
            case DT_JMPREL:   jmprel = d->d_un.d_ptr; break;
            case DT_PLTRELSZ: jmprel_sz = d->d_un.d_val; break;
            case DT_SYMTAB:   symtab_addr = d->d_un.d_ptr; break;
            case DT_STRTAB:   strtab_addr = d->d_un.d_ptr; break;
#if defined(__LP64__)
            case DT_RELA:     rela = d->d_un.d_ptr; break;
            case DT_RELASZ:   rela_sz = d->d_un.d_val; break;
            case DT_RELAENT:  rela_ent = d->d_un.d_val; break;
#else
            case DT_REL:      rela = d->d_un.d_ptr; break;
            case DT_RELSZ:    rela_sz = d->d_un.d_val; break;
            case DT_RELENT:   rela_ent = d->d_un.d_val; break;
#endif
        }
    }

    if (!symtab_addr || !strtab_addr) return;

    auto resolve_addr = [base](uintptr_t raw) -> uintptr_t {
        return (raw >= base) ? raw : (base + raw);
    };

    auto *symtab = reinterpret_cast<ElfW(Sym)*>(resolve_addr(symtab_addr));
    const char *strtab = reinterpret_cast<const char*>(resolve_addr(strtab_addr));
    if (jmprel) jmprel = resolve_addr(jmprel);
    if (rela)   rela   = resolve_addr(rela);

    auto check_and_patch = [&](uintptr_t r_offset, uint32_t r_sym) {
        if (r_sym == 0) return;
        const char *name = strtab + symtab[r_sym].st_name;
        if (strcmp(name, sym_name) != 0) return;

        void **got_slot = reinterpret_cast<void **>(base + r_offset);
        patch_got_slot_cg(got_slot, hook_func);
        out_slots.push_back(got_slot);
    };

    if (jmprel) {
#if defined(__LP64__)
        size_t ent_size = sizeof(ElfW(Rela));
        for (size_t off = 0; off < jmprel_sz; off += ent_size) {
            auto *rel = reinterpret_cast<ElfW(Rela) *>(jmprel + off);
            check_and_patch(rel->r_offset, ELF64_R_SYM(rel->r_info));
        }
#else
        size_t ent_size = sizeof(ElfW(Rel));
        for (size_t off = 0; off < jmprel_sz; off += ent_size) {
            auto *rel = reinterpret_cast<ElfW(Rel) *>(jmprel + off);
            check_and_patch(rel->r_offset, ELF32_R_SYM(rel->r_info));
        }
#endif
    }

    if (rela && rela_ent > 0) {
#if defined(__LP64__)
        for (size_t off = 0; off < rela_sz; off += rela_ent) {
            auto *rel = reinterpret_cast<ElfW(Rela) *>(rela + off);
            check_and_patch(rel->r_offset, ELF64_R_SYM(rel->r_info));
        }
#else
        for (size_t off = 0; off < rela_sz; off += rela_ent) {
            auto *rel = reinterpret_cast<ElfW(Rel) *>(rela + off);
            check_and_patch(rel->r_offset, ELF32_R_SYM(rel->r_info));
        }
#endif
    }
}

struct cg_patch_ctx {
    void *fork_target;
    void *vfork_target;
};

static int patch_all_cg_cb(struct dl_phdr_info *info, size_t, void *data) {
    if (!info->dlpi_addr) return 0;
    auto *ctx = static_cast<cg_patch_ctx *>(data);

    patch_got_for_sym(info->dlpi_addr, "fork",
                      ctx->fork_target, (void *)fork_replacement,
                      g_fork_got_slots);
    patch_got_for_sym(info->dlpi_addr, "vfork",
                      ctx->vfork_target, (void *)fork_replacement,
                      g_vfork_got_slots);
    return 0;
}

void enable_child_gating(child_gating_config const &cfg) {
    child_gating_mode = cfg.mode;
    injected_libraries = cfg.injected_libraries;

    LOGI("[child_gating] enabling child gating (GOT patch)");

    real_fork = reinterpret_cast<pid_t(*)()>(dlsym(RTLD_DEFAULT, "fork"));
    real_vfork = reinterpret_cast<pid_t(*)()>(dlsym(RTLD_DEFAULT, "vfork"));
    LOGI("[child_gating] fork=%p  vfork=%p", real_fork, real_vfork);

    if (!real_fork || !real_vfork) {
        LOGE("[child_gating] failed to resolve fork/vfork");
        return;
    }

    cg_patch_ctx ctx{(void *)real_fork, (void *)real_vfork};
    dl_iterate_phdr(patch_all_cg_cb, &ctx);

    LOGI("[child_gating] patched %zu fork + %zu vfork GOT slot(s)",
         g_fork_got_slots.size(), g_vfork_got_slots.size());
}

