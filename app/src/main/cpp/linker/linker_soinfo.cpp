/*
 * Copyright (C) 2016 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "linker_soinfo.h"

#include <dlfcn.h>
#include <elf.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/param.h>
#include "linker_utils.h"
#include "linker.h"
#include "stdlib.h"
#include "linker_config.h"
#include "log.h"
#include "linker_phdr.h"
#include "linker_gnu_hash.h"
#include "linker_globals.h"
#include "linker_relocate.h"
#include "linker_main.h"
int g_argc = 0;
char **g_argv = nullptr;
char **g_envp = nullptr;

// Enable the slow lookup path if symbol lookups should be logged.
static bool is_lookup_tracing_enabled() {
    return false;
}

void *soinfo::to_handle() {
    return reinterpret_cast<void *>(handle_);
}

static void call_function(const char *function_name __unused,
                          linker_ctor_function_t function,
                          const char *realpath __unused) {
    if (function == nullptr ||
        reinterpret_cast<uintptr_t>(function) == static_cast<uintptr_t>(-1)) {
        return;
    }
    LOGD("[ Calling d-tor %s @ %p for '%s' ]", function_name, function, realpath);
    function(g_argc, g_argv, g_envp);
    LOGD("[ Done calling d-tor %s @ %p for '%s' ]", function_name, function, realpath);

}
static inline bool check_symbol_version(const ElfW(Versym)* ver_table, uint32_t sym_idx,
                                        const ElfW(Versym) verneed) {
    if (ver_table == nullptr) return true;
    const uint32_t verdef = ver_table[sym_idx];
    return (verneed == kVersymNotNeeded) ?
           !(verdef & kVersymHiddenBit) :
           verneed == (verdef & ~kVersymHiddenBit);
}
template<typename F>
static inline void call_array(const char *array_name __unused, F *functions, size_t count,
                              bool reverse, const char *realpath) {
    if (functions == nullptr) {
        return;
    }

    LOGD("[ Calling %s (size %zd) @ %p for '%s' ]", array_name, count, functions, realpath);


    int begin = reverse ? (count - 1) : 0;
    int end = reverse ? -1 : count;
    int step = reverse ? -1 : 1;
    //
    for (int i = begin; i != end; i += step) {
        LOGD("[ %s[%d] == %p ]", array_name, i, functions[i]);
        call_function("function", functions[i], realpath);
    }

    LOGD("[ Done calling %s for '%s' ]", array_name, realpath);
}

void soinfo::call_constructors() {
    if (constructors_called) {
        return;
    }
    // We set constructors_called before actually calling the constructors, otherwise it doesn't
    // protect against recursive constructor calls. One simple example of constructor recursion
    // is the libc debug malloc, which is implemented in libc_malloc_debug_leak.so:
    // 1. The program depends on libc, so libc's constructor is called here.
    // 2. The libc constructor calls dlopen() to load libc_malloc_debug_leak.so.
    // 3. dlopen() calls the constructors on the newly created
    //    soinfo for libc_malloc_debug_leak.so.
    // 4. The debug .so depends on libc, so CallConstructors is
    //    called again with the libc soinfo. If it doesn't trigger the early-
    //    out above, the libc constructor will be called again (recursively!).
    constructors_called = true;
    if (!is_main_executable() && preinit_array_ != nullptr) {
        // The GNU dynamic linker silently ignores these, but we warn the developer.
        LOGI("\"%s\": ignoring DT_PREINIT_ARRAY in shared library!", get_realpath());
    }
    get_children().for_each([](soinfo *si) {
        si->call_constructors();
    });
    // DT_INIT should be called before DT_INIT_ARRAY if both are present.
    call_function("DT_INIT", init_func_, get_realpath());
    call_array("DT_INIT_ARRAY", init_array_, init_array_count_, false, get_realpath());

}

size_t soinfo::increment_ref_count() {
    return ++local_group_root_->ref_count_;
}

const char *soinfo::get_soname() const {
    return soname_.c_str();
}

android_namespace_t *soinfo::get_primary_namespace() {
    return primary_namespace_;
}

android_namespace_list_t &soinfo::get_secondary_namespaces() {
    return secondary_namespaces_;
}

uint32_t soinfo::get_dt_flags_1() const {

    return dt_flags_1_;

}


soinfo_list_t &soinfo::get_parents() {

    return parents_;

}

soinfo::soinfo(android_namespace_t *ns, const char *realpath, const struct stat *file_stat,
               off64_t file_offset, int rtld_flags) {
    memset(this, 0, sizeof(*this));
    if (realpath != nullptr) {
        realpath_ = realpath;
    }

    flags_ = FLAG_NEW_SOINFO;
    version_ = SOINFO_VERSION;

    if (file_stat != nullptr) {
        this->st_dev_ = file_stat->st_dev;
        this->st_ino_ = file_stat->st_ino;
        this->file_offset_ = file_offset;
    }

    this->rtld_flags_ = rtld_flags;
    this->primary_namespace_ = ns;
}

void soinfo::generate_handle() {
    // Make sure the handle is unique and does not collide
    // with special values which are RTLD_DEFAULT and RTLD_NEXT.
    arc4random_buf(&handle_, sizeof(handle_));
}

soinfo::~soinfo() {

}

bool soinfo::is_mapped_by_caller() const {
    return (flags_ & FLAG_MAPPED_BY_CALLER) != 0;

}

size_t soinfo::get_gap_size() const {
    return gap_size_;
}

void soinfo::remove_all_links() {
    // 1. Untie connected soinfos from 'this'.
    children_.for_each([&](soinfo *child) {
        child->parents_.remove_if([&](const soinfo *parent) {
            return parent == this;
        });
    });
    parents_.for_each([&](soinfo *parent) {
        parent->children_.remove_if([&](const soinfo *child) {
            return child == this;
        });
    });
    // 2. Remove from the primary namespace
    primary_namespace_->remove_soinfo(this);
    primary_namespace_ = nullptr;
    // 3. Remove from secondary namespaces
    secondary_namespaces_.for_each([&](android_namespace_t *ns) {
        ns->remove_soinfo(this);
    });

    // 4. Once everything untied - clear local lists.
    parents_.clear();
    children_.clear();
    secondary_namespaces_.clear();
}

ElfW(Addr) soinfo::get_gap_start() const {
    return gap_start_;
}

const char *fix_dt_needed(const char *dt_needed, const char *sopath __unused) {
#if !defined(__LP64__)
    // Work around incorrect DT_NEEDED entries for old apps: http://b/21364029
  int app_target_api_level = get_application_target_sdk_version();
  if (app_target_api_level < 23) {
    const char* bname = basename(dt_needed);
    if (bname != dt_needed) {
      DL_WARN_documented_change(23,
                                "invalid-dt_needed-entries-enforced-for-api-level-23",
                                "library \"%s\" has invalid DT_NEEDED entry \"%s\"",
                                sopath, dt_needed, app_target_api_level);
      add_dlwarning(sopath, "invalid DT_NEEDED entry",  dt_needed);
    }

    return bname;
  }
#endif
    return dt_needed;
}

void soinfo::set_dt_runpath(const char *path) {
    std::vector<std::string> runpaths;
    split_path(path, ":", &runpaths);
    std::string origin = dirname(get_realpath());
// FIXME: add $PLATFORM.
    std::vector<std::pair<std::string, std::string>> params = {
            {"ORIGIN", origin},
            {"LIB",    kLibPath},
    };
    for (auto &&s: runpaths) {
        format_string(&s, params);
    }

    resolve_paths(runpaths, &dt_runpath_);
}

void soinfo::set_soname(const char *soname) {
#if defined(__work_around_b_24465209__)
    if (has_min_version(2)) {
    soname_ = soname;
  }
  strlcpy(old_name_, soname_.c_str(), sizeof(old_name_));
#else
    soname_ = soname;
#endif
}

void soinfo::set_dt_flags_1(uint32_t dt_flags_1) {
    if (has_min_version(1)) {
        if ((dt_flags_1 & DF_1_GLOBAL) != 0) {
            rtld_flags_ |= RTLD_GLOBAL;
        }

        if ((dt_flags_1 & DF_1_NODELETE) != 0) {
            rtld_flags_ |= RTLD_NODELETE;
        }

        dt_flags_1_ = dt_flags_1;
    }
}

const char *soinfo::get_realpath() const {
#if defined(__work_around_b_24465209__)
    if (has_min_version(2)) {
    return realpath_.c_str();
  } else {
    return old_name_;
  }
#else
    return realpath_.c_str();
#endif
}

void soinfo::add_child(soinfo *child) {
    if (has_min_version(0)) {
        child->parents_.push_back(this);
        this->children_.push_back(child);
    }
}

bool soinfo::is_linked() const {
    return (flags_ & FLAG_LINKED) != 0;
}

void soinfo::set_mapped_by_caller(bool mapped_by_caller) {
    if (mapped_by_caller) {
        flags_ |= FLAG_MAPPED_BY_CALLER;
    } else {
        flags_ &= ~FLAG_MAPPED_BY_CALLER;
    }
}

void soinfo::set_gap_start(Elf64_Addr gap_start) {
    gap_start_ = gap_start;
}

void soinfo::set_gap_size(size_t gap_size) {
    gap_size_ = gap_size;
}

ElfW(Addr) soinfo::get_verdef_ptr() const {
    return verdef_ptr_;

}

size_t soinfo::get_verdef_cnt() const {
    return verdef_cnt_;

}

const char *soinfo::get_string(Elf64_Word index) const {


    return strtab_ + index;
}

soinfo_list_t &soinfo::get_children() {
    return children_;
}

SymbolLookupLib soinfo::get_lookup_lib() {
    SymbolLookupLib result{};
    result.si_ = this;

    // For libs that only have SysV hashes, leave the gnu_bloom_filter_ field NULL to signal that
    // the fallback code path is needed.
    if (!is_gnu_hash()) {
        return result;
    }

    result.gnu_maskwords_ = gnu_maskwords_;
    result.gnu_shift2_ = gnu_shift2_;
    result.gnu_bloom_filter_ = gnu_bloom_filter_;

    result.strtab_ = strtab_;
    result.strtab_size_ = strtab_size_;
    result.symtab_ = symtab_;
    result.versym_ = get_versym_table();

    result.gnu_chain_ = gnu_chain_;
    result.gnu_nbucket_ = gnu_nbucket_;
    result.gnu_bucket_ = gnu_bucket_;

    return result;
}

bool soinfo::is_image_linked() const {
    return (flags_ & FLAG_IMAGE_LINKED) != 0;
}

bool soinfo::link_image(const SymbolLookupList &lookup_list, soinfo *local_group_root,
                        const android_dlextinfo *extinfo, size_t *relro_fd_offset) {
    if (is_image_linked()) {
        return true;
    }
    local_group_root_ = local_group_root;
    if (local_group_root_ == nullptr) {
        local_group_root_ = this;
    }
    if ((flags_ & FLAG_LINKER) == 0 && local_group_root_ == this) {
        target_sdk_version_ = get_application_target_sdk_version();
    }
    if (!relocate(lookup_list)) {
        LOGE("relocate failed");
        return false;
    }
    LOGD("[ finished linking %s ]", get_realpath());
    if (!is_linked() && !protect_relro()){
        return false;
    }
    set_image_linked();
    return true;
}

bool soinfo::is_gnu_hash() const {
    return (flags_ & FLAG_GNU_HASH) != 0;
}

void soinfo::set_linked() {
    flags_ |= FLAG_LINKED;
}

soinfo *soinfo::get_local_group_root() const {
    return local_group_root_;
}

bool soinfo::is_main_executable() const {
    return (flags_ & FLAG_EXE) != 0;
}

ElfW(Addr) soinfo::get_verneed_ptr() const {
    return verneed_ptr_;
}

size_t soinfo::get_verneed_cnt() const {
    return verneed_cnt_;
}

const soinfo_list_t &soinfo::get_children() const {
    return children_;
}

//这段代码是动态链接器中用于处理 RELR 类型重定位的函数。REL(Relocation)R(ELR) 是一种优化的重定位格式，
// 旨在通过减少重定位条目的数量来减少二进制大小和加载时间。
//REL和RELR重定位：在传统的 ELF 重定位格式中（如 REL 和 RELA）
//每个重定位条目都明确指定了需要重定位的地址和如何进行重定位。与之相比，RELR 重定位使用一种更为紧凑的表示方式，其中一个条目可以指示多个地址进行相同类型的重定位。
//处理逻辑：函数遍历 relr_ 数组，该数组包含 RELR 重定位条目，直到达到 relr_count_ 指示的末尾。对于每个条目，它根据条目的值执行以下操作：
bool soinfo::relocate_relr() {
    ElfW(Relr) *begin = relr_;
    ElfW(Relr) *end = relr_ + relr_count_;
    constexpr size_t wordsize = sizeof(ElfW(Addr));

    ElfW(Addr) base = 0;
    for (ElfW(Relr) *current = begin; current < end; ++current) {
        ElfW(Relr) entry = *current;
        ElfW(Addr) offset;

        if ((entry & 1) == 0) {
            // Even entry: encodes the offset for next relocation.
            offset = static_cast<ElfW(Addr)>(entry);
            apply_relr_reloc(offset);
            // Set base offset for subsequent bitmap entries.
            base = offset + wordsize;
            continue;
        }

        // Odd entry: encodes bitmap for relocations starting at base.
        offset = base;
        while (entry != 0) {
            entry >>= 1;
            if ((entry & 1) != 0) {
                apply_relr_reloc(offset);
            }
            offset += wordsize;
        }

        // Advance base offset by 63 words for 64-bit platforms,
        // or 31 words for 32-bit platforms.
        base += (8 * wordsize - 1) * wordsize;
    }
    return true;
}

void soinfo::apply_relr_reloc(Elf64_Addr offset) {
    ElfW(Addr) address = offset + load_bias;
    *reinterpret_cast<ElfW(Addr) *>(address) += load_bias;
}


template <bool IsGeneral>
__attribute__((noinline)) static const ElfW(Sym)*
soinfo_do_lookup_impl(const char* name, const version_info* vi,
                      soinfo** si_found_in, const SymbolLookupList& lookup_list) {
    SymbolName elf_symbol_name(name);
    LOGI("elf_symbol_name %s  vi = %p ", name,vi);
    //findIn target first
    if (vi!= nullptr && vi->target_si!= nullptr){
        LOGI("find Symbol in target so first %s ,symbol name %s", vi->target_si->get_realpath(),name);
        const Elf64_Sym *pSym = vi->target_si->find_symbol_by_name(elf_symbol_name, vi);
        if (pSym!= nullptr){
             soinfo *pSoinfo = const_cast<soinfo *>(vi->target_si);
            *si_found_in = pSoinfo;
            return pSym;
        }
    }
    //find in system
    LOGI("find elf_symbol_name in system %s", name);
    auto solist = linker_get_solist();
    for (auto it = solist.begin(); it != solist.end(); it++) {
        //find in system
        soinfo* soinfo = static_cast<struct soinfo *>(*it);
        LOGI("find in soinfo %s", soinfo->get_realpath());
        //try find in system
        const Elf64_Sym *pSym = soinfo->find_symbol_by_name(elf_symbol_name, vi);
        if (pSym!= nullptr){
            *si_found_in = soinfo;
            LOGI("find in solist %s  name %s ", soinfo->get_realpath(),name);
            return pSym;
        }

    }
    return nullptr;
}
const ElfW(Sym)* soinfo_do_lookup(const char* name, const version_info* vi,
                                  soinfo** si_found_in, const SymbolLookupList& lookup_list) {
    return lookup_list.needs_slow_path() ?
           soinfo_do_lookup_impl<true>(name, vi, si_found_in, lookup_list) :
           soinfo_do_lookup_impl<false>(name, vi, si_found_in, lookup_list);
}
/**
 * 这段代码位于 Android 动态链接器的 soinfo 类中，
 * 具体负责查找给定符号的版本信息。它尝试根据符号的版本索引，从 VersionTracker 对象中获取与该符号相关联的版本信息。下面是代码的详细解释：
 * 函数参数
const VersionTracker& version_tracker：一个引用到 VersionTracker 对象的常量引用，该对象包含了当前共享库依赖的所有版本定义（verdef）和版本需求（verneed）的信息。
ElfW(Word) sym：表示符号在符号表中的索引。
const char* sym_name：符号的名称。
const version_info** vi：一个指向 version_info 指针的指针，用于输出找到的版本信息。
获取符号的版本索引
使用 get_versym(sym) 方法获取指向符号版本索引的指针。这个版本索引在 ELF 文件的 .gnu.version 或类似的节中为每个符号定义。
如果 sym_ver_ptr 为 nullptr（即，没有找到符号的版本索引），则将 sym_ver 设置为 0，表示没有版本信息。否则，sym_ver 被设置为指针指向的值。
检查版本索引并获取版本信息
如果版本索引不是 VER_NDX_LOCAL（表示符号是本地的，不导出或不导入）也不是 VER_NDX_GLOBAL（表示符号是全局的，不具有特定的版本控制），则尝试从 version_tracker 中获取与 sym_ver 对应的版本信息。
如果没有找到对应的版本信息（*vi == nullptr），则打印错误信息，指出无法找到对应于给定版本索引的 verneed 或 verdef，并返回 false。
处理无版本信息的情况
如果版本索引是 VER_NDX_LOCAL 或 VER_NDX_GLOBAL，表示该符号没有特定的版本信息，将输出参数 *vi 设置为 nullptr。
返回值
如果成功找到了版本信息或者确定符号没有版本信息，则函数返回 true。如果无法找到与符号关联的版本信息，则返回 false。
 * @param version_tracker
 * @param sym
 * @param sym_name
 * @param vi
 * @return
 */
bool soinfo::lookup_version_info(const VersionTracker &version_tracker, Elf64_Word sym,
                                 const char *sym_name, const version_info **vi) {
    const ElfW(Versym)* sym_ver_ptr = get_versym(sym);
    ElfW(Versym) sym_ver = sym_ver_ptr == nullptr ? 0 : *sym_ver_ptr;

    if (sym_ver != VER_NDX_LOCAL && sym_ver != VER_NDX_GLOBAL) {
        *vi = version_tracker.get_version_info(sym_ver);
        if (*vi == nullptr) {
            LOGE("cannot find verneed/verdef for version index=%d "
                   "referenced by symbol \"%s\" at \"%s\"", sym_ver, sym_name, get_realpath());
            return false;
        }
    } else {
        // there is no version info
        *vi = nullptr;
    }
    return true;
}

const ElfW(Versym) *soinfo::get_versym(size_t n) const {
    auto table = get_versym_table();
    return table ? table + n : nullptr;
}

const ElfW(Sym) *
soinfo::find_symbol_by_name(SymbolName &symbol_name, const version_info *vi) const {
//    LOGI("find_symbol_by_name is_gnu_hash %d", is_gnu_hash());
    return is_gnu_hash() ? gnu_lookup(symbol_name, vi) : elf_lookup(symbol_name, vi);
}

const ElfW(Sym) *soinfo::gnu_lookup(SymbolName &symbol_name, const version_info *vi) const {
    const uint32_t hash = symbol_name.gnu_hash();

    constexpr uint32_t kBloomMaskBits = sizeof(ElfW(Addr)) * 8;
    const uint32_t word_num = (hash / kBloomMaskBits) & gnu_maskwords_;
    const ElfW(Addr) bloom_word = gnu_bloom_filter_[word_num];
    const uint32_t h1 = hash % kBloomMaskBits;
    const uint32_t h2 = (hash >> gnu_shift2_) % kBloomMaskBits;

//    TRACE_TYPE("SEARCH %s in %s@%p (gnu)",
//               symbol_name.get_name(), get_realpath(), reinterpret_cast<void*>(base));

    // test against bloom filter
    if ((1 & (bloom_word >> h1) & (bloom_word >> h2)) == 0) {
//        TRACE_TYPE( "NOT FOUND %s in %s@%p",
//                   symbol_name.get_name(), get_realpath(), reinterpret_cast<void*>(base));

        return nullptr;
    }

    // bloom test says "probably yes"...
    uint32_t n = gnu_bucket_[hash % gnu_nbucket_];

    if (n == 0) {
//        TRACE_TYPE( "NOT FOUND %s in %s@%p",
//                   symbol_name.get_name(), get_realpath(), reinterpret_cast<void*>(base));

        return nullptr;
    }

    const ElfW(Versym) verneed = find_verdef_version_index(this, vi);
    const ElfW(Versym)* versym = get_versym_table();

    do {
        ElfW(Sym)* s = symtab_ + n;
        if (((gnu_chain_[n] ^ hash) >> 1) == 0 &&
            check_symbol_version(versym, n, verneed) &&
            strcmp(get_string(s->st_name), symbol_name.get_name()) == 0 &&
            is_symbol_global_and_defined(this, s)) {
            TRACE_TYPE( "FOUND %s in %s (%p) %zd",
                       symbol_name.get_name(), get_realpath(), reinterpret_cast<void*>(s->st_value),
                       static_cast<size_t>(s->st_size));
            return symtab_ + n;
        }
    } while ((gnu_chain_[n++] & 1) == 0);

//    TRACE_TYPE( "NOT FOUND %s in %s@%p",
//               symbol_name.get_name(), get_realpath(), reinterpret_cast<void*>(base));

    return nullptr;
}

const ElfW(Sym) *soinfo::elf_lookup(SymbolName &symbol_name, const version_info *vi) const {
    return nullptr;
}

bool soinfo::protect_relro() {
    if (phdr_table_protect_gnu_relro(phdr, phnum, load_bias) < 0) {
        LOGE("can't enable GNU RELRO protection for \"%s\": %s",
               get_realpath(), strerror(errno));
        return false;
    }
    return true;
}

void soinfo::set_image_linked() {
    flags_ |= FLAG_IMAGE_LINKED;
}


SymbolLookupList::SymbolLookupList(const soinfo_list_t &global_group,
                                   const soinfo_list_t &local_group) {
    slow_path_count_ += is_lookup_tracing_enabled();
    libs_.reserve(1 + global_group.size() + local_group.size());
    // Reserve a space in front for DT_SYMBOLIC lookup.
    libs_.push_back(SymbolLookupLib{});
    global_group.for_each([this](soinfo *si) {
        libs_.push_back(si->get_lookup_lib());
        slow_path_count_ += libs_.back().needs_sysv_lookup();
    });
}

void SymbolLookupList::set_dt_symbolic_lib(soinfo *lib) {
    slow_path_count_ -= libs_[0].needs_sysv_lookup();
    libs_[0] = lib ? lib->get_lookup_lib() : SymbolLookupLib();
    slow_path_count_ += libs_[0].needs_sysv_lookup();
    begin_ = lib ? &libs_[0] : &libs_[1];
}

uint32_t SymbolName::gnu_hash() {
    if (!has_gnu_hash_) {
        gnu_hash_ = calculate_gnu_hash(name_).first;
        has_gnu_hash_ = true;
    }
    return gnu_hash_;
}
