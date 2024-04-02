//
// Created by PC5000 on 2024/3/26.
//

#ifndef LINKERBRIDGE_LINKER_H
#define LINKERBRIDGE_LINKER_H
#include "android/dlext.h"
#include "linker_soinfo.h"
#define ON 1 //enbale hide in proc/self/maps
#define OFF 0 // do not hide

#define ENBALE_HIDE_MAP ON
#define FAKE_MAPS_NAME ".Imy"
#define FAKE_SEGMENT_NAME "linker_alloc"
#define SUPPORTED_DT_FLAGS_1 (DF_1_NOW | DF_1_GLOBAL | DF_1_NODELETE | DF_1_PIE)
int get_application_target_sdk_version();


// Class used construct version dependency graph.
class VersionTracker {
public:
    VersionTracker() = default;
    bool init(const soinfo* si_from);

    const version_info* get_version_info(ElfW(Versym) source_symver) const;
private:
    bool init_verneed(const soinfo* si_from);
    bool init_verdef(const soinfo* si_from);
    void add_version_info(size_t source_index, ElfW(Word) elf_hash,
                          const char* ver_name, const soinfo* target_si);

    std::vector<version_info> version_infos;

    DISALLOW_COPY_AND_ASSIGN(VersionTracker);
};
bool get_transparent_hugepages_supported();
void* do_dlopen(const char* name, int flags,
                const android_dlextinfo* extinfo,
                const void* caller_addr);
struct address_space_params {
    void* start_addr = nullptr;
    size_t reserved_size = 0;
    bool must_use_address = false;
};

struct platform_properties {
#if defined(__aarch64__)
    bool bti_supported = false;
#endif
};

ElfW(Versym) find_verdef_version_index(const soinfo* si, const version_info* vi);


#endif //LINKERBRIDGE_LINKER_H
