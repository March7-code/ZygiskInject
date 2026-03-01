#include "remapper.h"

#include <link.h>
#include <sys/mman.h>

#include <cerrno>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "log.h"

// Struct to hold a single entry in /proc/maps/
// Format: 7ac49c2000(start)-7ac4a26000(end) r--p (permissions) 00000000(offset) 00:00 0 (dev) 1245 (inode) /apex/com.android.runtime/bin/linker64 (path) // NOLINT
struct PROCMAPSINFO {
    uintptr_t start, end, offset;
    uint8_t perms;
    ino_t inode;
    std::string dev;
    std::string path;
};


std::vector<PROCMAPSINFO> get_modules_by_name(const std::string &m_name) {
    std::string process_maps_locations = "/proc/self/maps";

    std::vector<PROCMAPSINFO> maps;

    char buffer[512];
    FILE *fp = fopen(process_maps_locations.c_str(), "re");

    if (fp == nullptr) {
        return maps;
    }

    while (fgets(buffer, sizeof(buffer), fp)) {
        if (strstr(buffer, m_name.c_str())) {
            PROCMAPSINFO info{};
            char perms[10] = {0};
            char path[255] = {0};
            char dev[25] = {0};
            unsigned long long inode = 0;

            int parsed = sscanf(
                buffer,
                "%" SCNxPTR "-%" SCNxPTR " %9s %" SCNxPTR " %24s %llu %254s",
                &info.start, &info.end, perms, &info.offset, dev, &inode, path);
            if (parsed < 7) {
                continue;
            }
            info.inode = (ino_t)inode;

            /* Store process permissions in the struct directly via bitwise operations */
            if (strchr(perms, 'r')) info.perms |= PROT_READ;
            if (strchr(perms, 'w')) info.perms |= PROT_WRITE;
            if (strchr(perms, 'x')) info.perms |= PROT_EXEC;

            info.dev = dev;
            info.path = path;

            maps.push_back(info);
        }
    }

    fclose(fp);

    return maps;
}

void remap_lib(std::string lib_path) {
    std::string lib_name = lib_path.substr(lib_path.find_last_of("/\\") + 1);

    std::vector<PROCMAPSINFO> maps = get_modules_by_name(lib_name);
    if (maps.size() == 0) {
        return;
    }

    LOGI("Remapping %s", lib_name.c_str());

    for (const PROCMAPSINFO &info : maps) {
        void *address = reinterpret_cast<void *>(info.start);
        size_t size = info.end - info.start;
        if (size == 0) {
            continue;
        }

        void *map = mmap(nullptr, size, PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if (map == MAP_FAILED) {
            LOGE("Failed to allocate memory: %s", strerror(errno));
            continue;
        }

        if ((info.perms & PROT_READ) == 0) {
            LOGI("Removing memory protection: %s", info.path.c_str());
            if (mprotect(address, size, PROT_READ) != 0) {
                LOGE("Failed to update memory protection for %s: %s",
                     info.path.c_str(), strerror(errno));
                munmap(map, size);
                continue;
            }
        }

        /* Copy the in-memory data to new virtual location via the memove, allocate and commit it via mremap */
        std::memmove(map, address, size);
        void *remap_result = mremap(map, size, size,
                                    MREMAP_MAYMOVE | MREMAP_FIXED,
                                    reinterpret_cast<void *>(info.start));
        if (remap_result == MAP_FAILED) {
            LOGE("Failed to remap segment %s: %s", info.path.c_str(), strerror(errno));
            munmap(map, size);
            continue;
        }

        /* Re-apply memory protections */
        if (mprotect(reinterpret_cast<void *>(info.start), size, info.perms) != 0) {
            LOGE("Failed to restore memory protection for %s: %s",
                 info.path.c_str(), strerror(errno));
            continue;
        }

        LOGI("Remapped segment %s at %p with size %zu", info.path.c_str(), map, size);
    }

    LOGI("Remapped");
}
