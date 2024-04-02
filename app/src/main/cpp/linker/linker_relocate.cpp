/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include "linker_relocate.h"

#include <elf.h>
#include <link.h>
#include "log.h"
#include <type_traits>

#include "linker.h"
#include "linker_reloc_iterators.h"
#include "linker_relocs.h"

class Relocator {
public:
    Relocator(const VersionTracker &version_tracker, const SymbolLookupList &lookup_list)
            : version_tracker(version_tracker), lookup_list(lookup_list) {}

    soinfo *si = nullptr;
    const char *si_strtab = nullptr;
    size_t si_strtab_size = 0;
    ElfW(Sym) *si_symtab = nullptr;

    const VersionTracker &version_tracker;
    const SymbolLookupList &lookup_list;

    // Cache key
    ElfW(Word) cache_sym_val = 0;
    // Cache value
    const ElfW(Sym) *cache_sym = nullptr;
    soinfo *cache_si = nullptr;

    std::vector<TlsDynamicResolverArg> *tlsdesc_args;
//    std::vector<std::pair<TlsDescriptor*, size_t>> deferred_tlsdesc_relocs;
    size_t tls_tp_base = 0;

    __attribute__((always_inline))
    const char *get_string(ElfW(Word) index) {

        return si_strtab + index;
    }
};

enum class RelocMode {
    // Fast path for JUMP_SLOT relocations.
    JumpTable,
    // Fast path for typical relocations: ABSOLUTE, GLOB_DAT, or RELATIVE.
    Typical,
    // Handle all relocation types, relocations in text sections, and statistics/tracing.
    General,
};

static bool is_tls_reloc(ElfW(Word) type) {
    switch (type) {
        case R_GENERIC_TLS_DTPMOD:
        case R_GENERIC_TLS_DTPREL:
        case R_GENERIC_TLS_TPREL:
        case R_GENERIC_TLSDESC:
            return true;
        default:
            return false;
    }
}
struct linker_stats_t {
    int count[kRelocMax];
};
static linker_stats_t linker_stats;

void count_relocation(RelocationKind kind) {
    ++linker_stats.count[kind];
}

template<bool DoLogging>
__attribute__((always_inline))
static inline bool lookup_symbol(Relocator &relocator, uint32_t r_sym, const char *sym_name,
                                 soinfo **found_in, const ElfW(Sym) **sym) {
    if (r_sym == relocator.cache_sym_val) {
        *found_in = relocator.cache_si;
        *sym = relocator.cache_sym;
        count_relocation_if<DoLogging>(kRelocSymbolCached);
    }else {
        const version_info* vi = nullptr;
        if (!relocator.si->lookup_version_info(relocator.version_tracker, r_sym, sym_name, &vi)) {
            return false;
        }
        soinfo* local_found_in = nullptr;
//        LOGI("call soinfo_do_lookup ");
        const ElfW(Sym)* local_sym = soinfo_do_lookup(sym_name, vi, &local_found_in, relocator.lookup_list);
        relocator.cache_sym_val = r_sym;
        relocator.cache_si = local_found_in;
        relocator.cache_sym = local_sym;
        *found_in = local_found_in;
        *sym = local_sym;
    }
    if (*sym== nullptr){
        if (ELF_ST_BIND(relocator.si_symtab[r_sym].st_info) != STB_WEAK) {
            LOGE("cannot locate symbol \"%s\" referenced by \"%s\"...", sym_name, relocator.si->get_realpath());
            return false;
        }
    }
    count_relocation_if<DoLogging>(kRelocSymbol);
    return true;
}

template<RelocMode Mode>
__attribute__((always_inline))
static bool process_relocation_impl(Relocator &relocator, const rel_t &reloc) {
    constexpr bool IsGeneral = Mode == RelocMode::General;
    void *const rel_target = reinterpret_cast<void *>(reloc.r_offset + relocator.si->load_bias);
#if defined(__LP64__)
    const uint32_t r_type = ELF64_R_TYPE(reloc.r_info);
    const uint32_t r_sym = ELF64_R_SYM(reloc.r_info);
#else
    const uint32_t r_type = ELF32_R_TYPE(reloc.r_info);
    const uint32_t r_sym = ELF32_R_SYM(reloc.r_info);
#endif
    soinfo *found_in = nullptr;
    const ElfW(Sym) *sym = nullptr;
    const char *sym_name = nullptr;
    ElfW(Addr) sym_addr = 0;
    if (r_sym != 0) {
        sym_name = relocator.get_string(relocator.si_symtab[r_sym].st_name);
    }
    LOGI(" r_type = %d, r_sym = %d, sym_name = %s", r_type, r_sym, sym_name);
#if defined(__LP64__)
    const bool handle_text_relocs = false;
    auto protect_segments = []() { return true; };
    auto unprotect_segments = []() { return true; };
#else
    const bool handle_text_relocs = IsGeneral && relocator.si->has_text_relocations;
  auto protect_segments = [&]() {
    // Make .text executable.
    if (phdr_table_protect_segments(relocator.si->phdr, relocator.si->phnum,
                                    relocator.si->load_bias) < 0) {
      DL_ERR("can't protect segments for \"%s\": %s",
             relocator.si->get_realpath(), strerror(errno));
      return false;
    }
    return true;
  };
  auto unprotect_segments = [&]() {
    // Make .text writable.
    if (phdr_table_unprotect_segments(relocator.si->phdr, relocator.si->phnum,
                                      relocator.si->load_bias) < 0) {
      DL_ERR("can't unprotect loadable segments for \"%s\": %s",
             relocator.si->get_realpath(), strerror(errno));
      return false;
    }
    return true;
  };
#endif
    auto trace_reloc = [](const char *fmt, ...) __printflike(2, 3) {
        va_list ap;
        va_start(ap, fmt);
        LOGD(fmt, ap);
        va_end(ap);
    };
    // Skip symbol lookup for R_GENERIC_NONE relocations.
    if (__predict_false(r_type == 0)) {
        trace_reloc("RELO NONE");
        return true;
    }
#if defined(USE_RELA)
    auto get_addend_rel = [&]() -> ElfW(Addr) { return reloc.r_addend; };
    auto get_addend_norel = [&]() -> ElfW(Addr) { return reloc.r_addend; };
#else
    auto get_addend_rel   = [&]() -> ElfW(Addr) { return *static_cast<ElfW(Addr)*>(rel_target); };
  auto get_addend_norel = [&]() -> ElfW(Addr) { return 0; };
#endif
    if (IsGeneral && is_tls_reloc(r_type)) {
        if (r_sym == 0) {
            // By convention in ld.bfd and lld, an omitted symbol on a TLS relocation
            // is a reference to the current module.
            found_in = relocator.si;
        } else if (ELF_ST_BIND(relocator.si_symtab[r_sym].st_info) == STB_LOCAL) {
            // In certain situations, the Gold linker accesses a TLS symbol using a
            // relocation to an STB_LOCAL symbol in .dynsym of either STT_SECTION or
            // STT_TLS type. Bionic doesn't support these relocations, so issue an
            // error. References:
            //  - https://groups.google.com/d/topic/generic-abi/dJ4_Y78aQ2M/discussion
            //  - https://sourceware.org/bugzilla/show_bug.cgi?id=17699
            sym = &relocator.si_symtab[r_sym];
            LOGE("unexpected TLS reference to local symbol \"%s\" in \"%s\": sym type %d, rel type %u",
                 sym_name, relocator.si->get_realpath(), ELF_ST_TYPE(sym->st_info), r_type);
            return false;
        } else if (!lookup_symbol<IsGeneral>(relocator, r_sym, sym_name, &found_in, &sym)) {
            return false;
        }
        if (found_in != nullptr && found_in->get_tls() == nullptr) {
            // sym_name can be nullptr if r_sym is 0. A linker should never output an ELF file like this.
            LOGE("TLS relocation refers to symbol \"%s\" in solib \"%s\" with no TLS segment",
                   sym_name, found_in->get_realpath());
            return false;
        }
        if (sym != nullptr) {
            if (ELF_ST_TYPE(sym->st_info) != STT_TLS) {
                // A toolchain should never output a relocation like this.
                LOGE("reference to non-TLS symbol \"%s\" from TLS relocation in \"%s\"",
                       sym_name, relocator.si->get_realpath());
                return false;
            }
            sym_addr = sym->st_value;
        }
//        LOGI("is tls reloc ");
    } else {
//        LOGI("not tls reloc r_type = %d r_sym %i", r_type,r_sym);
        if (r_sym == 0) {
            // Do nothing.
        } else {
            if (!lookup_symbol<IsGeneral>(relocator, r_sym, sym_name, &found_in, &sym)) return false;

            if (sym != nullptr) {
                const bool should_protect_segments = handle_text_relocs &&
                                                     found_in == relocator.si &&
                                                     ELF_ST_TYPE(sym->st_info) == STT_GNU_IFUNC;
                if (should_protect_segments && !protect_segments()) return false;
                sym_addr = found_in->resolve_symbol_address(sym);
                if (should_protect_segments && !unprotect_segments()) return false;
            }else if constexpr (IsGeneral) {
// A weak reference to an undefined symbol. We typically use a zero symbol address, but
                // use the relocation base for PC-relative relocations, so that the value written is zero.
                switch (r_type) {
#if defined(__x86_64__)
                    case R_X86_64_PC32:
            sym_addr = reinterpret_cast<ElfW(Addr)>(rel_target);
            break;
#elif defined(__i386__)
                    case R_386_PC32:
            sym_addr = reinterpret_cast<ElfW(Addr)>(rel_target);
            break;
#endif
                }
            }
        }
    }
    if constexpr (IsGeneral || Mode == RelocMode::JumpTable) {
//        LOGI("isJumpTable or General");
        if (r_type == R_GENERIC_JUMP_SLOT) {
            count_relocation_if<IsGeneral>(kRelocAbsolute);
            const ElfW(Addr) result = sym_addr + get_addend_norel();
//            LOGI("sym_addr %llx ",result);
            *static_cast<ElfW(Addr)*>(rel_target) = result;
            //replace the value of rel_target with result
            LOGD("We Done R_GENERIC_JUMP_SLOT in system only  symbolName %s  %llx",sym_name,result);
            return true;
        }
    }
    if constexpr (IsGeneral || Mode == RelocMode::Typical) {
        //Almost all dynamic relocations are of one of these types, and most will be
        // R_GENERIC_ABSOLUTE. The platform typically uses RELR instead, but R_GENERIC_RELATIVE is
        // common in non-platform binaries.
        if (r_type == R_GENERIC_ABSOLUTE) {
            count_relocation_if<IsGeneral>(kRelocAbsolute);
            const ElfW(Addr) result = sym_addr + get_addend_rel();
            trace_reloc("RELO ABSOLUTE %16p <- %16p %s",
                        rel_target, reinterpret_cast<void*>(result), sym_name);
            *static_cast<ElfW(Addr)*>(rel_target) = result;
            return true;
        } else if (r_type == R_GENERIC_GLOB_DAT) {
            // The i386 psABI specifies that R_386_GLOB_DAT doesn't have an addend. The ARM ELF ABI
            // document (IHI0044F) specifies that R_ARM_GLOB_DAT has an addend, but Bionic isn't adding
            // it.
            count_relocation_if<IsGeneral>(kRelocAbsolute);
            const ElfW(Addr) result = sym_addr + get_addend_norel();
            trace_reloc("RELO GLOB_DAT %16p <- %16p %s",
                        rel_target, reinterpret_cast<void*>(result), sym_name);
            *static_cast<ElfW(Addr)*>(rel_target) = result;
            return true;
        } else if (r_type == R_GENERIC_RELATIVE) {
            // In practice, r_sym is always zero, but if it weren't, the linker would still look up the
            // referenced symbol (and abort if the symbol isn't found), even though it isn't used.
            count_relocation_if<IsGeneral>(kRelocRelative);
            const ElfW(Addr) result = relocator.si->load_bias + get_addend_rel();
            trace_reloc("RELO RELATIVE %16p <- %16p",
                        rel_target, reinterpret_cast<void*>(result));
            *static_cast<ElfW(Addr)*>(rel_target) = result;
            return true;
        }
    }
    //ptrace 远程调用so=>
    //dlopen()
    //dlclose()
    return true;
}

__attribute__((noinline))
static bool process_relocation_general(Relocator &relocator, const rel_t &reloc) {
    return process_relocation_impl<RelocMode::General>(relocator, reloc);
}

template<RelocMode Mode>
__attribute__((always_inline))
static inline bool process_relocation(Relocator &relocator, const rel_t &reloc) {
    return Mode == RelocMode::General ?
           process_relocation_general(relocator, reloc) :
           process_relocation_impl<Mode>(relocator, reloc);
}

template<RelocMode Mode>
__attribute__((noinline))
static bool plain_relocate_impl(Relocator &relocator, rel_t *rels, size_t rel_count) {
    for (size_t i = 0; i < rel_count; ++i) {
        if (!process_relocation<Mode>(relocator, rels[i])) {
            return false;
        }
    }
    return true;
}

static bool needs_slow_relocate_loop(const Relocator &relocator __unused) {
#if STATS
    // TODO: This could become a run-time flag.
  return true;
#endif
#if !defined(__LP64__)
    if (relocator.si->has_text_relocations) return true;
#endif
//    if (g_ld_debug_verbosity > LINKER_VERBOSITY_TRACE) {
//        // If linker TRACE() is enabled, then each relocation is logged.
//        return true;
//    }
    return false;
}

template<RelocMode OptMode, typename ...Args>
static bool plain_relocate(Relocator &relocator, Args ...args) {
    return needs_slow_relocate_loop(relocator) ?
           plain_relocate_impl<RelocMode::General>(relocator, args...) :
           plain_relocate_impl<OptMode>(relocator, args...);
}

/**
 * 这段代码是 Android 动态链接器（linker）的一部分，负责在加载共享库（如 .so 文件）时进行重定位。重定位是动态链接过程中的一个关键步骤，
 * 它确保了共享库中引用的各种符号（如函数和变量）被正确地更新为它们在内存中的实际地址。
 * 这个过程对于实现共享库的动态加载和共享是必要的。
 * @param lookup_list
 * @return
 */
bool soinfo::relocate(const SymbolLookupList &lookup_list) {
    VersionTracker version_tracker;
    if (!version_tracker.init(this)) {
        return false;
    }
    LOGI("in soinfo::relocate, version_tracker.init(this) success");
    Relocator relocator(version_tracker, lookup_list);
    relocator.si = this;
    relocator.si_strtab = strtab_;
    relocator.si_strtab_size = strtab_size_;
    relocator.si_symtab = symtab_;
    relocator.tlsdesc_args = &tlsdesc_args_;
//    relocator.tls_tp_base = __libc_shared_globals()->static_tls_layout.offset_thread_pointer();

//    if (android_relocs_ != nullptr) {
//        // check signature
//        if (android_relocs_size_ > 3 &&
//            android_relocs_[0] == 'A' &&
//            android_relocs_[1] == 'P' &&
//            android_relocs_[2] == 'S' &&
//            android_relocs_[3] == '2') {
//            DEBUG("[ android relocating %s ]", get_realpath());
//
//            const uint8_t* packed_relocs = android_relocs_ + 4;
//            const size_t packed_relocs_size = android_relocs_size_ - 4;
//
//            if (!packed_relocate<RelocMode::Typical>(relocator, sleb128_decoder(packed_relocs, packed_relocs_size))) {
//                return false;
//            }
//        } else {
//            DL_ERR("bad android relocation header.");
//            return false;
//        }
//    }

    if (relr_ != nullptr) {
        LOGE("[ relocating %s relr ]", get_realpath());
        if (!relocate_relr()) {
            return false;
        }
    }

#if defined(USE_RELA)
    if (rela_ != nullptr) {
        LOGD("[ relocating %s rela ] count %zu rela_= %p", get_realpath(), rela_count_, rela_);
        if (!plain_relocate<RelocMode::Typical>(relocator, rela_, rela_count_)) {
            LOGE("plain_relocate<RelocMode::Typical> failed");
            return false;
        }
    }
    if (plt_rela_ != nullptr) {
        LOGD("[ relocating %s plt_relas ] count %zu plt_rela_%p ", get_realpath(), plt_rela_count_, plt_rela_);
        if (!plain_relocate<RelocMode::JumpTable>(relocator, plt_rela_, plt_rela_count_)) {
            return false;
        }
    }
#else
    if (rel_ != nullptr) {
    DEBUG("[ relocating %s rel ]", get_realpath());
    if (!plain_relocate<RelocMode::Typical>(relocator, rel_, rel_count_)) {
      return false;
    }
  }
  if (plt_rel_ != nullptr) {
    DEBUG("[ relocating %s plt rel ]", get_realpath());
    if (!plain_relocate<RelocMode::JumpTable>(relocator, plt_rel_, plt_rel_count_)) {
      return false;
    }
  }
#endif

    // Once the tlsdesc_args_ vector's size is finalized, we can write the addresses of its elements
    // into the TLSDESC relocations.
#if defined(__aarch64__)
    // Bionic currently only implements TLSDESC for arm64. //TODO
//    for (const std::pair<TlsDescriptor*, size_t>& pair : relocator.deferred_tlsdesc_relocs) {
//        TlsDescriptor* desc = pair.first;
//        desc->func = tlsdesc_resolver_dynamic;
//        desc->arg = reinterpret_cast<size_t>(&tlsdesc_args_[pair.second]);
//    }
#endif
    return true;
}


