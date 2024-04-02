//
// Created by PC5000 on 2024/3/29.
//


#include <sys/user.h>
#include "bionic_elf_tls.h"
#include "sys/param.h"
bool __bionic_get_tls_segment(const ElfW(Phdr)* phdr_table, size_t phdr_count,
        ElfW(Addr) load_bias, TlsSegment* out){
    for (size_t i = 0; i < phdr_count; ++i) {
        const ElfW(Phdr)& phdr = phdr_table[i];
        if (phdr.p_type == PT_TLS) {
            *out = TlsSegment {
                    phdr.p_memsz,
                    phdr.p_align,
                    reinterpret_cast<void*>(load_bias + phdr.p_vaddr),
                    phdr.p_filesz,
            };
            return true;
        }
    }
    return false;
}

// Return true if the alignment of a TLS segment is a valid power-of-two. Also
// cap the alignment if it's too high.
bool __bionic_check_tls_alignment(size_t* alignment) {
    // N.B. The size does not need to be a multiple of the alignment. With
    // ld.bfd (or after using binutils' strip), the TLS segment's size isn't
    // rounded up.
    if (*alignment == 0 || !powerof2(*alignment)) {
        return false;
    }
    // Bionic only respects TLS alignment up to one page.
    *alignment = MIN(*alignment, PAGE_SIZE);
    return true;
}