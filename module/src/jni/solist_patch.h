#ifndef ZYGISKFRIDA_SOLIST_PATCH_H
#define ZYGISKFRIDA_SOLIST_PATCH_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Remove the soinfo entry for the library loaded at `load_address` from the
// linker's internal solist, making it invisible to dl_iterate_phdr / dladdr.
// Returns true on success.
bool solist_remove_lib(uintptr_t load_address);

#ifdef __cplusplus
}
#endif

#endif // ZYGISKFRIDA_SOLIST_PATCH_H
