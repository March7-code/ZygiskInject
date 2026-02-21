#include "solist_patch.h"

#include <dlfcn.h>
#include <elf.h>
#include <inttypes.h>
#include <link.h>
#include <stdint.h>
#include <string.h>
#include <sys/auxv.h>

#include "log.h"
#include "xdl.h"

// Linker internal symbol names for solist head and tail pointers.
// These are mangled names of the static globals:
//   static soinfo* solist  -> __dl__ZL6solist
//   static soinfo* sonext  -> __dl__ZL6sonext
#define LINKER_SYM_SOLIST  "__dl__ZL6solist"
#define LINKER_SYM_SONEXT  "__dl__ZL6sonext"

// Maximum bytes to scan in a soinfo struct when probing field offsets.
#define SOINFO_SCAN_SIZE   0x200

static const char *get_linker_path() {
#if defined(__LP64__)
    return "/apex/com.android.runtime/bin/linker64";
#else
    return "/apex/com.android.runtime/bin/linker";
#endif
}

// Read a pointer-sized value at byte offset `off` inside the soinfo at `si`.
static inline uintptr_t si_read_ptr(uintptr_t si, size_t off) {
    return *(uintptr_t *)(si + off);
}

// Write a pointer-sized value at byte offset `off` inside the soinfo at `si`.
static inline void si_write_ptr(uintptr_t si, size_t off, uintptr_t val) {
    *(uintptr_t *)(si + off) = val;
}

// Probe the soinfo struct pointed to by `si` to find the byte offsets of the
// `base` field and the `next` pointer field.
//
// Strategy (same as AndKittyInjector, simplified for in-process use):
//   - Scan the first SOINFO_SCAN_SIZE bytes in pointer-sized steps.
//   - The first pointer that resolves to a valid ELF mapping (magic check) is
//     treated as `base`.
//   - The `strtab` pointer (DT_STRTAB value from the ELF's dynamic segment)
//     appears a fixed distance after `next` in every known Android version.
//     Specifically: next is 2 pointers before strtab.
//   - We locate strtab by matching the value we read from the ELF's own
//     PT_DYNAMIC segment, then back up 2 * sizeof(uintptr_t).
static bool find_soinfo_offsets(uintptr_t si,
                                size_t *out_base_off,
                                size_t *out_next_off) {
    // First pass: find base_offset by looking for a pointer whose target
    // starts with the ELF magic bytes.
    size_t base_off = (size_t)-1;
    uintptr_t base_val = 0;

    for (size_t i = 0; i + sizeof(uintptr_t) <= SOINFO_SCAN_SIZE; i += sizeof(uintptr_t)) {
        uintptr_t candidate = si_read_ptr(si, i);
        if (candidate < 0x1000) continue;  // skip nulls and small integers
        // Check ELF magic at the candidate address
        if (memcmp((void *)candidate, ELFMAG, SELFMAG) == 0) {
            base_off = i;
            base_val = candidate;
            break;
        }
    }

    if (base_off == (size_t)-1) {
        LOGE("[solist_patch] failed to find base offset in soinfo");
        return false;
    }

    // Second pass: find strtab by reading the ELF's PT_DYNAMIC segment and
    // extracting the DT_STRTAB value, then scanning soinfo for that value.
    uintptr_t strtab_val = 0;
    ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *)base_val;
    ElfW(Phdr) *phdr = (ElfW(Phdr) *)(base_val + ehdr->e_phoff);
    for (int p = 0; p < ehdr->e_phnum; p++) {
        if (phdr[p].p_type == PT_DYNAMIC) {
            ElfW(Dyn) *dyn = (ElfW(Dyn) *)(base_val + phdr[p].p_vaddr);
            for (; dyn->d_tag != DT_NULL; dyn++) {
                if (dyn->d_tag == DT_STRTAB) {
                    strtab_val = base_val + dyn->d_un.d_ptr;
                    break;
                }
            }
            break;
        }
    }

    if (strtab_val == 0) {
        LOGE("[solist_patch] failed to read DT_STRTAB from ELF at 0x%" PRIxPTR, base_val);
        return false;
    }

    // Scan soinfo for the strtab value; next is 2 pointers before it.
    for (size_t i = 0; i + sizeof(uintptr_t) <= SOINFO_SCAN_SIZE; i += sizeof(uintptr_t)) {
        if (si_read_ptr(si, i) == strtab_val) {
            if (i < 2 * sizeof(uintptr_t)) {
                LOGE("[solist_patch] strtab found too early in soinfo (off=0x%zx)", i);
                return false;
            }
            *out_base_off = base_off;
            *out_next_off = i - 2 * sizeof(uintptr_t);
            LOGI("[solist_patch] soinfo offsets: base=0x%zx next=0x%zx", base_off, *out_next_off);
            return true;
        }
    }

    LOGE("[solist_patch] failed to find strtab in soinfo scan");
    return false;
}

bool solist_remove_lib(uintptr_t load_address) {
    if (load_address == 0) {
        LOGE("[solist_patch] invalid load_address");
        return false;
    }

    // Open the linker to resolve its internal symbols via xdl_dsym.
    // XDL_TRY_FORCE_LOAD is needed on Android 7+ where the linker is in a
    // separate namespace.
    void *linker_handle = xdl_open(get_linker_path(), XDL_TRY_FORCE_LOAD);
    if (!linker_handle) {
        // Fallback: try the legacy path
#if defined(__LP64__)
        linker_handle = xdl_open("/system/bin/linker64", XDL_TRY_FORCE_LOAD);
#else
        linker_handle = xdl_open("/system/bin/linker", XDL_TRY_FORCE_LOAD);
#endif
    }
    if (!linker_handle) {
        LOGE("[solist_patch] failed to open linker via xdl");
        return false;
    }

    // Resolve solist and sonext symbol addresses.
    size_t sym_size = 0;
    uintptr_t *solist_ptr = (uintptr_t *)xdl_dsym(linker_handle, LINKER_SYM_SOLIST, &sym_size);
    uintptr_t *sonext_ptr = (uintptr_t *)xdl_dsym(linker_handle, LINKER_SYM_SONEXT, &sym_size);

    xdl_close(linker_handle);

    if (!solist_ptr || !sonext_ptr) {
        LOGE("[solist_patch] failed to resolve solist/sonext symbols");
        return false;
    }

    uintptr_t solist_head = *solist_ptr;
    uintptr_t sonext_val  = *sonext_ptr;

    if (solist_head == 0) {
        LOGE("[solist_patch] solist is empty");
        return false;
    }

    // Use the tail node (sonext) as a known-good soinfo to probe field offsets,
    // since it is always a valid, fully-initialized soinfo.
    size_t base_off = 0, next_off = 0;
    if (!find_soinfo_offsets(sonext_val, &base_off, &next_off)) {
        return false;
    }

    // Traverse the linked list to find the soinfo whose base == load_address.
    uintptr_t prev = 0;
    uintptr_t curr = solist_head;

    while (curr != 0) {
        uintptr_t curr_base = si_read_ptr(curr, base_off);
        if (curr_base == load_address) {
            break;
        }
        prev = curr;
        curr = si_read_ptr(curr, next_off);
    }

    if (curr == 0) {
        LOGE("[solist_patch] soinfo for load_address 0x%" PRIxPTR " not found in solist", load_address);
        return false;
    }

    uintptr_t next = si_read_ptr(curr, next_off);

    // Unlink: prev->next = curr->next
    if (prev == 0) {
        // Removing the head node
        *solist_ptr = next;
    } else {
        si_write_ptr(prev, next_off, next);
    }

    // If we removed the tail, update sonext to point to prev.
    if (curr == sonext_val) {
        *sonext_ptr = prev;
    }

    LOGI("[solist_patch] removed soinfo for 0x%" PRIxPTR " from solist", load_address);
    return true;
}
