/*
 * Copyright (C) 2012 The Android Open Source Project
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

#include "linker_phdr.h"

#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "inttypes.h"
#include "linker.h"
#include "log.h"
#include "../libc/platform/bionic/page.h"
#include "linker_utils.h"
#include "fake_mmap.h"
// Default PMD size for x86_64 and aarch64 (2MB).

#define MAYBE_MAP_FLAG(x, from, to)  (((x) & (from)) ? (to) : 0)
#define PFLAGS_TO_PROT(x)            (MAYBE_MAP_FLAG((x), PF_X, PROT_EXEC) | \
                                      MAYBE_MAP_FLAG((x), PF_R, PROT_READ) | \
                                      MAYBE_MAP_FLAG((x), PF_W, PROT_WRITE))
static constexpr size_t kPmdSize = (1UL << 21);
constexpr unsigned kLibraryAlignmentBits = 18;
constexpr size_t kLibraryAlignment = 1UL << kLibraryAlignmentBits;

static int GetTargetElfMachine() {
#if defined(__arm__)
    return EM_ARM;
#elif defined(__aarch64__)
    return EM_AARCH64;
#elif defined(__i386__)
    return EM_386;
#elif defined(__x86_64__)
  return EM_X86_64;
#endif
}

/* Used internally by phdr_table_protect_gnu_relro and
 * phdr_table_unprotect_gnu_relro.
 */
static int _phdr_table_set_gnu_relro_prot(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                          ElfW(Addr) load_bias, int prot_flags) {
    const ElfW(Phdr)* phdr = phdr_table;
    const ElfW(Phdr)* phdr_limit = phdr + phdr_count;

    for (phdr = phdr_table; phdr < phdr_limit; phdr++) {
        if (phdr->p_type != PT_GNU_RELRO) {
            continue;
        }

        // Tricky: what happens when the relro segment does not start
        // or end at page boundaries? We're going to be over-protective
        // here and put every page touched by the segment as read-only.

        // This seems to match Ian Lance Taylor's description of the
        // feature at http://www.airs.com/blog/archives/189.

        //    Extract:
        //       Note that the current dynamic linker code will only work
        //       correctly if the PT_GNU_RELRO segment starts on a page
        //       boundary. This is because the dynamic linker rounds the
        //       p_vaddr field down to the previous page boundary. If
        //       there is anything on the page which should not be read-only,
        //       the program is likely to fail at runtime. So in effect the
        //       linker must only emit a PT_GNU_RELRO segment if it ensures
        //       that it starts on a page boundary.
        ElfW(Addr) seg_page_start = PAGE_START(phdr->p_vaddr) + load_bias;
        ElfW(Addr) seg_page_end   = PAGE_END(phdr->p_vaddr + phdr->p_memsz) + load_bias;

        int ret = mprotect(reinterpret_cast<void*>(seg_page_start),
                           seg_page_end - seg_page_start,
                           prot_flags);
        if (ret < 0) {
            return -1;
        }
    }
    return 0;
}
int phdr_table_protect_gnu_relro(const ElfW(Phdr)* phdr_table,
                                 size_t phdr_count, ElfW(Addr) load_bias) {
    return _phdr_table_set_gnu_relro_prot(phdr_table, phdr_count, load_bias, PROT_READ);
}
bool ElfReader::CheckFileRange(ElfW(Addr) offset, size_t size, size_t alignment) {
    off64_t range_start;
    off64_t range_end;

    // Only header can be located at the 0 offset... This function called to
    // check DYNSYM and DYNAMIC sections and phdr/shdr - none of them can be
    // at offset 0.

    return offset > 0 &&
           safe_add(&range_start, file_offset_, offset) &&
           safe_add(&range_end, range_start, size) &&
           (range_start < file_size_) &&
           (range_end <= file_size_) &&
           ((offset % alignment) == 0);
}

static const char *EM_to_string(int em) {
    if (em == EM_386) return "EM_386";
    if (em == EM_AARCH64) return "EM_AARCH64";
    if (em == EM_ARM) return "EM_ARM";
    if (em == EM_X86_64) return "EM_X86_64";
    return "EM_???";
}

bool ElfReader::VerifyElfHeader() {
    //与ELF文件的魔数（magic number）ELFMAG。魔数是用来标识文件类型的一串特定的字节序列。对于ELF文件，这个魔数是4个字节，分别是0x7F, E, L, F。
    // 如果header_.e_ident的前SELFMAG（4）个字节与ELFMAG不匹配，说明这不是一个有效的ELF文件。在这种情况下，会打印一条错误日志，并且方法返回false。
    if (memcmp(header_.e_ident, ELFMAG, SELFMAG) != 0) {
        LOGE("\"%s\" has bad ELF magic: %02x%02x%02x%02x", name_.c_str(),
             header_.e_ident[0], header_.e_ident[1], header_.e_ident[2], header_.e_ident[3]);
        return false;
    }
    return true;
}

//读取程序头表（Program Header Table），并将其映射到一个只读的、私有的、匿名的内存区域中
bool ElfReader::ReadProgramHeaders() {
    //1. 读取程序头表的数量
    phdr_num_ = header_.e_phnum; //即 program header table 的数量

    //2. 验证程序头表的大小
    //这一步检查程序头表的数量是否在合理范围内，
    // 即至少有1个，且总大小不超过64KiB。
    // 这是基于内核的同样限制，旨在防止不合理的程序头表大小。如果不满足条件，则输出错误并返回false。
    if (phdr_num_ < 1 || phdr_num_ > 65536 / sizeof(ElfW(Phdr))) {
        LOGE("\"%s\" has invalid e_phnum: %zd", name_.c_str(), phdr_num_);
        return false;
    }

    // 3. 边界检查
    //计算程序头表的总大小（size = phdr_num_ * sizeof(ElfW(Phdr))），
    // 然后调用CheckFileRange函数检查这个范围内的数据是否完全位于文件内，并且与ElfW(Phdr)的对齐要求相匹配。如果检查失败，则输出错误并返回false。
    size_t size = phdr_num_ * sizeof(ElfW(Phdr));

    if (!CheckFileRange(header_.e_phoff, size, alignof(ElfW(Phdr)))) {
        LOGE("\"%s\" has invalid phdr offset/size: %zu/%zu",
             name_.c_str(),
             static_cast<size_t>(header_.e_phoff),
             size);
        return false;
    }
    // 4. 映射程序头表到内存
    //使用phdr_fragment_.Map方法，通过文件描述符fd_将程序头表映射到内存中
    // 。file_offset_是文件的偏移量，header_.e_phoff是程序头表在文件中的偏移量，
    // size是需要映射的数据大小。如果映射失败，输出错误并使用strerror(errno)报告具体的错误原因，然后返回false。
    //打印 file_offset_、header_.e_phoff、size
    LOGD("file_offset_=%d, header_.e_phoff=%d, size=%d", file_offset_, header_.e_phoff, size);
    if (!phdr_fragment_.Map(fd_, file_offset_, header_.e_phoff, size)) {
        LOGE("\"%s\" phdr mmap failed: %s", name_.c_str(), strerror(errno));
        return false;
    }
    //5. 保存程序头表指针
    phdr_table_ = static_cast<ElfW(Phdr) *>(phdr_fragment_.data());
    LOGI(" phdr_table_=%p", phdr_table_);
    return true;
}

bool ElfReader::ReadElfHeader() {
    //read the elf header
    ssize_t rc = TEMP_FAILURE_RETRY(pread64(fd_, &header_, sizeof(header_), file_offset_));
    if (rc < 0) {
        LOGE("can't read file \"%s\": %s", name_.c_str(), strerror(errno));
        return false;
    }
    if (rc != sizeof(header_)) {
        LOGE("\"%s\" is too small to be an ELF executable: only found %zd bytes", name_.c_str(),
             static_cast<size_t>(rc));
        return false;
    }
    // Try to give a clear diagnostic for ELF class mismatches, since they're
    // an easy mistake to make during the 32-bit/64-bit transition period.
    //检查ELF类别
    //32位与64位匹配：根据编译目标（__LP64__定义时为64位），
    // 检查header_.e_ident[EI_CLASS]值是否与期望的ELF类别匹配（ELFCLASS32或ELFCLASS64）。
    // 不匹配的情况下会输出错误信息，这是为了处理在32位与64位转换期间可能出现的错误。
    int elf_class = header_.e_ident[EI_CLASS];
#if defined(__LP64__)
    if (elf_class != ELFCLASS64) {
        if (elf_class == ELFCLASS32) {
            LOGE("\"%s\" is 32-bit instead of 64-bit", name_.c_str());
        } else {
            LOGE("\"%s\" has unknown ELF class: %d", name_.c_str(), elf_class);
        }
        return false;
    }
#else
    if (elf_class != ELFCLASS32) {
    if (elf_class == ELFCLASS64) {
      DL_ERR("\"%s\" is 64-bit instead of 32-bit", name_.c_str());
    } else {
      DL_ERR("\"%s\" has unknown ELF class: %d", name_.c_str(), elf_class);
    }
    return false;
  }
#endif
    //检查字节序
    //字节序验证：检查header_.e_ident[EI_DATA]是否为ELFDATA2LSB，
    // 即判断文件是否为小端字节序。如果不是，输出错误信息并返回false。Android系统预期ELF文件为小端格式。
    if (header_.e_ident[EI_DATA] != ELFDATA2LSB) {
        LOGE("\"%s\" not little-endian: %d", name_.c_str(), header_.e_ident[EI_DATA]);
        return false;
    }
    //检查文件类型
    //文件类型验证：验证header_.e_type是否为ET_DYN，这意味着文件应该是一个共享对象文件。如果不是，输出错误信息并返回false。
    if (header_.e_type != ET_DYN) {
        LOGE("\"%s\" has unexpected e_type: %d", name_.c_str(), header_.e_type);
        return false;
    }
    //检查版本
    //版本验证：确保header_.e_version为EV_CURRENT，表示ELF头的版本是当前支持的版本。如果不是，输出错误信息并返回false。
    if (header_.e_version != EV_CURRENT) {
        LOGE("\"%s\" has unexpected e_version: %d", name_.c_str(), header_.e_version);
        return false;
    }
    //检查目标机器类型
    //机器类型验证：通过header_.e_machine与GetTargetElfMachine()返回值的比较，确保ELF文件是为当前架构编译的。如果不匹配，输出错误信息并返回false
    // 。EM_to_string函数用于将机器类型转换为可读字符串。
    if (header_.e_machine != GetTargetElfMachine()) {
        LOGE("\"%s\" is for %s (%d) instead of %s (%d)",
             name_.c_str(),
             EM_to_string(header_.e_machine), header_.e_machine,
             EM_to_string(GetTargetElfMachine()), GetTargetElfMachine());
        return false;
    }
    //检查节头部大小
    //节头部大小验证：检查header_.e_shentsize是否为sizeof(ElfW(Shdr))，以确保节头部的大小是正确的。如果不是，根据应用目标SDK版本，可能输出错误或警告信息，并返回false。
    //Elf64_Shdr结构体定义了一个ELF（Executable and Linkable Format）文件中的节头部（Section Header）。
    // 在64位系统中，这个结构体用于描述文件中每个节（Section）的属性和位置。
    // 节是ELF文件的组成部分，用于存储程序的不同类型的数据，比如代码、数据、符号表、重定位信息等。每个节头部提供了足够的信息，
    // 以便加载器或链接器可以正确地处理和放置节中的数据。
    //
    //以下是Elf64_Shdr各个字段的含义：
    //
    //sh_name：这是节名字符串表索引，指向节名称。节名字符串表是一个特殊的节（.shstrtab），包含了所有节的名字。
    //sh_type：指定节的类型，如是否是可执行代码、数据、符号表等。
    //sh_flags：标志位，指定节的属性，如是否可写、可执行、在进程执行时是否需要被载入内存等。
    //sh_addr：如果节在程序执行时需要被载入内存，这个字段指定节在内存中的起始地址。
    //sh_offset：节的偏移量，即从文件头到节内容开始处的字节偏移。
    //sh_size：节的长度，以字节为单位。
    //sh_link：额外的信息索引，具体含义依赖于节的类型。例如，在符号表节中，它是关联的字符串表节的索引。
    //sh_info：额外的信息，具体含义依赖于节的类型。例如，在重定位节中，它可能表示重定位应用的数量。
    //sh_addralign：节的地址对齐要求。节的地址在加载时需要是sh_addralign的倍数。
    //sh_entsize：如果节中包含固定大小的条目，如符号表，则表示每个条目的大小；如果节不包含此类条目或条目大小不固定，则为0。
    if (header_.e_shentsize != sizeof(ElfW(Shdr))) {
        return false;
    }
    //检查节头字符串表索引
    //节头字符串表索引验证：header_.e_shstrndx是节头字符串表的索引，如果这个值为0，表示文件头可能有问题。根据应用目标SDK版本，这也可能触发错误或警告，并返回false。
    if (header_.e_shstrndx == 0) {
        return false;
    }
    return true;
}

bool ElfReader::Read(const char *name, int fd, off64_t file_offset, off64_t file_size) {
    if (did_read_) {
        return true;
    }
    name_ = name;
    fd_ = fd;
    file_offset_ = file_offset;
    file_size_ = file_size;
    if (ReadElfHeader() &&
        VerifyElfHeader() &&
        ReadProgramHeaders() &&
        ReadSectionHeaders() &&
        ReadDynamicSection()) {
        did_read_ = true;
    }
    return did_read_;
}

ElfReader::ElfReader() : did_read_(false), did_load_(false), fd_(-1), file_offset_(0),
                         file_size_(0), phdr_num_(0),
                         phdr_table_(nullptr), shdr_table_(nullptr), shdr_num_(0),
                         dynamic_(nullptr), strtab_(nullptr),
                         strtab_size_(0), load_start_(nullptr), load_size_(0), load_bias_(0),
                         loaded_phdr_(nullptr),
                         mapped_by_caller_(false) {

}

/**
 * 与读取程序头的方式一致
 * @return
 */
bool ElfReader::ReadSectionHeaders() {
    shdr_num_ = header_.e_shnum;
    if (shdr_num_ == 0) {
        LOGE("\"%s\" has no section headers", name_.c_str());
        return false;
    }
    size_t size = shdr_num_ * sizeof(ElfW(Shdr));
    if (!CheckFileRange(header_.e_shoff, size, alignof(const ElfW(Shdr)))) {
        LOGE("\"%s\" has invalid shdr offset/size: %zu/%zu",
             name_.c_str(),
             static_cast<size_t>(header_.e_shoff),
             size);
        return false;
    }

    if (!shdr_fragment_.Map(fd_, file_offset_, header_.e_shoff, size)) {
        LOGE("\"%s\" shdr mmap failed: %s", name_.c_str(), strerror(errno));
        return false;
    }
    shdr_table_ = static_cast<const ElfW(Shdr) *>(shdr_fragment_.data());
    return true;
}

/**
 * 这个ElfReader::ReadDynamicSection方法是用来从一个ELF文件中读取动态节（.dynamic section）的信息，
 * 并将相关数据映射到内存中。动态节包含了动态链接信息，比如需要加载的共享库、重定位表等，
 * 对于动态链接器执行动态链接和加载至关重要。
 * @return
 */
bool ElfReader::ReadDynamicSection() {
    // 1. 查找动态节
    //遍历节头部表（shdr_table_），查找类型为SHT_DYNAMIC的节头部，即动态节。找到后，将dynamic_shdr指针设置为指向这个节头部。
    const ElfW(Shdr) *dynamic_shdr = nullptr;
    for (size_t i = 0; i < shdr_num_; ++i) {
        if (shdr_table_[i].sh_type == SHT_DYNAMIC) {
            dynamic_shdr = &shdr_table_[i];
            break;
        }
    }
    //2. 验证动态节的存在性
    //如果没有找到动态节，输出错误信息并返回false。
    if (dynamic_shdr == nullptr) {
        LOGE("\"%s\" .dynamic section header was not found", name_.c_str());
        return false;
    }
    //3. 匹配动态节偏移和大小
    //遍历程序头表（phdr_table_），找到类型为PT_DYNAMIC的程序头，这代表了动态节在文件中的偏移和大小。
    //确认从节头部表找到的动态节的偏移（sh_offset）和程序头表中的偏移（p_offset）相匹配，以及动态节的大小（sh_size）与程序头表中的文件大小（p_filesz）相匹配。如果不匹配，
    // 根据应用目标SDK版本输出错误或警告信息，并返回false。
    size_t pt_dynamic_offset = 0;
    size_t pt_dynamic_filesz = 0;
    for (size_t i = 0; i < phdr_num_; ++i) {
        const ElfW(Phdr) *phdr = &phdr_table_[i];
        //打印 所有phdr的值
        if (phdr->p_type == PT_DYNAMIC) {
            pt_dynamic_offset = phdr->p_offset;
            pt_dynamic_filesz = phdr->p_filesz;

        }
    }
    if (pt_dynamic_offset != dynamic_shdr->sh_offset) {

        LOGE("\"%s\" .dynamic section has invalid offset: 0x%zx, "
             "expected to match PT_DYNAMIC offset: 0x%zx",
             name_.c_str(),
             static_cast<size_t>(dynamic_shdr->sh_offset),
             pt_dynamic_offset);
        return false;
    }
    if (pt_dynamic_filesz != dynamic_shdr->sh_size) {
        LOGE("\"%s\" .dynamic section has invalid size: 0x%zx, "
             "expected to match PT_DYNAMIC filesz: 0x%zx",
             name_.c_str(),
             static_cast<size_t>(dynamic_shdr->sh_size),
             pt_dynamic_filesz);
        return false;
    }
    //4. 检查动态节链接的有效性
    //检查动态节的sh_link字段，它指向包含字符串表的节。如果sh_link超出了节头部表的范围，或链接到的节不是字符串表（SHT_STRTAB），输出错误信息并返回false。
    if (dynamic_shdr->sh_link >= shdr_num_) {
        LOGE("\"%s\" .dynamic section has invalid sh_link: %d",
             name_.c_str(),
             dynamic_shdr->sh_link);
        return false;
    }
    // 5. 映射动态节和字符串表到内存
    //使用dynamic_fragment_.Map将动态节内容映射到内存中。如果映射失败，输出错误信息并返回false。
    //使用strtab_fragment_.Map将由动态节链接的字符串表内容映射到内存中。如果映射失败，输出错误信息并返回false。

    const ElfW(Shdr) *strtab_shdr = &shdr_table_[dynamic_shdr->sh_link]; //通过动态节的sh_link字段找到字符串表节
    if (strtab_shdr->sh_type != SHT_STRTAB) {
        LOGE("\"%s\" .dynamic section has invalid link(%d) sh_type: %d (expected SHT_STRTAB)",
             name_.c_str(), dynamic_shdr->sh_link, strtab_shdr->sh_type);
        return false;
    }
    if (!CheckFileRange(dynamic_shdr->sh_offset, dynamic_shdr->sh_size, alignof(const ElfW(Dyn)))) {
        LOGE("\"%s\" has invalid offset/size of .dynamic section", name_.c_str());
        return false;
    }
    if (!dynamic_fragment_.Map(fd_, file_offset_, dynamic_shdr->sh_offset, dynamic_shdr->sh_size)) {
        LOGE("\"%s\" dynamic section mmap failed: %s", name_.c_str(), strerror(errno));
        return false;
    }
    dynamic_ = static_cast<const ElfW(Dyn) *>(dynamic_fragment_.data());
    if (!CheckFileRange(strtab_shdr->sh_offset, strtab_shdr->sh_size, alignof(const char))) {
        LOGE("\"%s\" has invalid offset/size of the .strtab section linked from .dynamic section",
             name_.c_str());
        return false;
    }
    if (!strtab_fragment_.Map(fd_, file_offset_, strtab_shdr->sh_offset, strtab_shdr->sh_size)) {
        LOGE("\"%s\" strtab section mmap failed: %s", name_.c_str(), strerror(errno));
        return false;
    }
    strtab_ = static_cast<const char *>(strtab_fragment_.data());
    strtab_size_ = strtab_fragment_.size();
    return true;
}

const char *ElfReader::get_string(Elf64_Word index) const {
    return strtab_ + index;
}


// Reserve a virtual address range such that if it's limits were extended to the next 2**align
// boundary, it would not overlap with any existing mappings.
static void *ReserveWithAlignmentPadding(size_t size, size_t mapping_align, size_t start_align,
                                         void **out_gap_start, size_t *out_gap_size) {
    int mmap_flags = MAP_PRIVATE | MAP_ANONYMOUS;
    // Reserve enough space to properly align the library's start address.
    mapping_align = std::max(mapping_align, start_align);
    if (mapping_align == PAGE_SIZE) {
        void *mmap_ptr = mmap(nullptr, size, PROT_NONE, mmap_flags, -1, 0);
        if (mmap_ptr == MAP_FAILED) {
            return nullptr;
        }
        return mmap_ptr;
    }

    // Minimum alignment of shared library gap. For efficiency, this should match the second level
    // page size of the platform.
#if defined(__LP64__)
    constexpr size_t kGapAlignment = 1ul << 21;  // 2MB
#else
    constexpr size_t kGapAlignment = 0;
#endif
    // Maximum gap size, in the units of kGapAlignment.
    constexpr size_t kMaxGapUnits = 32;
    // Allocate enough space so that the end of the desired region aligned up is still inside the
    // mapping.
    size_t mmap_size = align_up(size, mapping_align) + mapping_align - PAGE_SIZE;
    uint8_t *mmap_ptr =
            reinterpret_cast<uint8_t *>(mmap(nullptr, mmap_size, PROT_NONE, mmap_flags, -1, 0));
    if (mmap_ptr == MAP_FAILED) {
        return nullptr;
    }
    size_t gap_size = 0;
    size_t first_byte = reinterpret_cast<size_t>(align_up(mmap_ptr, mapping_align));
    size_t last_byte = reinterpret_cast<size_t>(align_down(mmap_ptr + mmap_size, mapping_align) -
                                                1);
    if (kGapAlignment && first_byte / kGapAlignment != last_byte / kGapAlignment) {
        // This library crosses a 2MB boundary and will fragment a new huge page.
        // Lets take advantage of that and insert a random number of inaccessible huge pages before that
        // to improve address randomization and make it harder to locate this library code by probing.
        munmap(mmap_ptr, mmap_size);
        mapping_align = std::max(mapping_align, kGapAlignment);
        gap_size =
                kGapAlignment *
                (is_first_stage_init() ? 1 : arc4random_uniform(kMaxGapUnits - 1) + 1);
        mmap_size = align_up(size + gap_size, mapping_align) + mapping_align - PAGE_SIZE;
        mmap_ptr = reinterpret_cast<uint8_t *>(mmap(nullptr, mmap_size, PROT_NONE, mmap_flags, -1,
                                                    0));
        if (mmap_ptr == MAP_FAILED) {
            return nullptr;
        }
    }

    uint8_t *gap_end, *gap_start;
    if (gap_size) {
        gap_end = align_down(mmap_ptr + mmap_size, kGapAlignment);
        gap_start = gap_end - gap_size;
    } else {
        gap_start = gap_end = mmap_ptr + mmap_size;
    }

    uint8_t *first = align_up(mmap_ptr, mapping_align);
    uint8_t *last = align_down(gap_start, mapping_align) - size;

    // arc4random* is not available in first stage init because /dev/urandom hasn't yet been
    // created. Don't randomize then.
    size_t n = is_first_stage_init() ? 0 : arc4random_uniform((last - first) / start_align + 1);
    uint8_t *start = first + n * start_align;
    // Unmap the extra space around the allocation.
    // Keep it mapped PROT_NONE on 64-bit targets where address space is plentiful to make it harder
    // to defeat ASLR by probing for readable memory mappings.
    munmap(mmap_ptr, start - mmap_ptr);
    munmap(start + size, gap_start - (start + size));
    if (gap_end != mmap_ptr + mmap_size) {
        munmap(gap_end, mmap_ptr + mmap_size - gap_end);
    }
    *out_gap_start = gap_start;
    *out_gap_size = gap_size;
    return start;
}

// Returns the maximum p_align associated with a loadable segment in the ELF
// program header table. Used to determine whether the file should be loaded at
// a specific virtual address alignment for use with huge pages.
size_t phdr_table_get_maximum_alignment(const ElfW(Phdr) *phdr_table, size_t phdr_count) {
    size_t maximum_alignment = PAGE_SIZE;

    for (size_t i = 0; i < phdr_count; ++i) {
        const ElfW(Phdr) *phdr = &phdr_table[i];

        // p_align must be 0, 1, or a positive, integral power of two.
        if (phdr->p_type != PT_LOAD || ((phdr->p_align & (phdr->p_align - 1)) != 0)) {
            continue;
        }

        if (phdr->p_align > maximum_alignment) {
            maximum_alignment = phdr->p_align;
        }
    }

#if defined(__LP64__)
    return maximum_alignment;
#else
    return PAGE_SIZE;
#endif
}

/* Returns the size of the extent of all the possibly non-contiguous
 * loadable segments in an ELF program header table. This corresponds
 * to the page-aligned size in bytes that needs to be reserved in the
 * process' address space. If there are no loadable segments, 0 is
 * returned.
 *
 * If out_min_vaddr or out_max_vaddr are not null, they will be
 * set to the minimum and maximum addresses of pages to be reserved,
 * or 0 if there is nothing to load.
 */
size_t phdr_table_get_load_size(const ElfW(Phdr) *phdr_table, size_t phdr_count,
                                ElfW(Addr) *out_min_vaddr,
                                ElfW(Addr) *out_max_vaddr) {
    ElfW(Addr) min_vaddr = UINTPTR_MAX;
    ElfW(Addr) max_vaddr = 0;

    bool found_pt_load = false;
    for (size_t i = 0; i < phdr_count; ++i) {
        const ElfW(Phdr) *phdr = &phdr_table[i];

        if (phdr->p_type != PT_LOAD) {
            continue;
        }
        found_pt_load = true;

        if (phdr->p_vaddr < min_vaddr) {
            min_vaddr = phdr->p_vaddr;
        }

        if (phdr->p_vaddr + phdr->p_memsz > max_vaddr) {
            max_vaddr = phdr->p_vaddr + phdr->p_memsz;
        }


    }
    if (!found_pt_load) {
        min_vaddr = 0;
    }
    min_vaddr = PAGE_START(min_vaddr);
    max_vaddr = PAGE_END(max_vaddr);


    if (out_min_vaddr != nullptr) {
        *out_min_vaddr = min_vaddr;
    }
    if (out_max_vaddr != nullptr) {
        *out_max_vaddr = max_vaddr;
    }
    return max_vaddr - min_vaddr;
}


// Reserve a virtual address range big enough to hold all loadable
// segments of a program header table. This is done by creating a
// private anonymous mmap() with PROT_NONE.
//这段代码是动态链接器中用于为将要加载的ELF文件预留足够的虚拟地址空间的过程。
// 它根据ELF文件中的程序头表信息，计算所有可加载段（loadable segments）所需的地址空间大小，
// 并尝试在进程的地址空间中预留这块区域。这一步是将ELF文件从磁盘映射到内存中的前置工作。
bool ElfReader::ReserveAddressSpace(address_space_params *address_space) {
    //计算可加载段所需的地址空间大小
    //phdr_table_get_load_size()函数计算ELF文件的程序头表中所有可加载段所需的总地址空间大小和最小虚拟地址（min_vaddr）
    // 。如果没有可加载段（load_size_ == 0），则输出错误信息并返回false。
    ElfW(Addr) min_vaddr;
    load_size_ = phdr_table_get_load_size(phdr_table_, phdr_num_, &min_vaddr);
    if (load_size_ == 0) {
        LOGE("\"%s\" has no loadable segments", name_.c_str());
        return false;
    }
    LOGI("load_size_ = %d reserved_size %d", load_size_, address_space->reserved_size);
    uint8_t *addr = reinterpret_cast<uint8_t *>(min_vaddr);
    void *start;
    if (load_size_ > address_space->reserved_size) {
        if (address_space->must_use_address) {
            LOGE("reserved address space %zd smaller than %zd bytes needed for \"%s\"",
                 load_size_ - address_space->reserved_size, load_size_, name_.c_str());
            return false;
        }
        size_t start_alignment = PAGE_SIZE;
        if (get_transparent_hugepages_supported() && get_application_target_sdk_version() >= 31) {
            size_t maximum_alignment = phdr_table_get_maximum_alignment(phdr_table_, phdr_num_);
            // Limit alignment to PMD size as other alignments reduce the number of
            // bits available for ASLR for no benefit.
            start_alignment = maximum_alignment == kPmdSize ? kPmdSize : PAGE_SIZE;
        }
        start = ReserveWithAlignmentPadding(load_size_, kLibraryAlignment, start_alignment,
                                            &gap_start_,
                                            &gap_size_);
        if (start == nullptr) {
            LOGE("couldn't reserve %zd bytes of address space for \"%s\"", load_size_,
                 name_.c_str());
            return false;
        }
    } else {
        start = address_space->start_addr;
        gap_start_ = nullptr;
        gap_size_ = 0;
        mapped_by_caller_ = true;

        // Update the reserved address space to subtract the space used by this library.
        address_space->start_addr =
                reinterpret_cast<uint8_t *>(address_space->start_addr) + load_size_;
        address_space->reserved_size -= load_size_;
    }

    load_start_ = start;
    load_bias_ = reinterpret_cast<uint8_t *>(start) - addr;
    LOGI("load_start_ = %p, load_bias_ = %x", load_start_, load_bias_);
    return true;
}

bool ElfReader::LoadSegments() {
    for (size_t i = 0; i < phdr_num_; ++i) {
        const ElfW(Phdr) *phdr = &phdr_table_[i];

        if (phdr->p_type != PT_LOAD) {
            continue;
        }
        // Segment addresses in memory.
        ElfW(Addr) seg_start = phdr->p_vaddr + load_bias_;
        ElfW(Addr) seg_end = seg_start + phdr->p_memsz;
        ElfW(Addr) seg_page_start = PAGE_START(seg_start);
        ElfW(Addr) seg_page_end = PAGE_END(seg_end);
        ElfW(Addr) seg_file_end = seg_start + phdr->p_filesz;
        // File offsets.
        ElfW(Addr) file_start = phdr->p_offset;
        ElfW(Addr) file_end = file_start + phdr->p_filesz;
        ElfW(Addr) file_page_start = PAGE_START(file_start);
        ElfW(Addr) file_length = file_end - file_page_start;
        if (file_size_ <= 0) {
            LOGE("\"%s\" invalid file size: %" PRId64, name_.c_str(), file_size_);
            return false;
        }
        if (file_end > static_cast<size_t>(file_size_)) {
            LOGE("invalid ELF file \"%s\" load segment[%zd]:"
                 " p_offset (%p) + p_filesz (%p) ( = %p) past end of file (0x%" PRIx64 ")",
                 name_.c_str(), i, reinterpret_cast<void *>(phdr->p_offset),
                 reinterpret_cast<void *>(phdr->p_filesz),
                 reinterpret_cast<void *>(file_end), file_size_);
            return false;
        }
        LOGI(" file_length = %d", file_length);
        if (file_length != 0) {
            int prot = PFLAGS_TO_PROT(phdr->p_flags);
            if ((prot & (PROT_EXEC | PROT_WRITE)) == (PROT_EXEC | PROT_WRITE)) {
                if (get_application_target_sdk_version() >= 26) {
                    LOGE("\"%s\": W+E load segments are not allowed", name_.c_str());
                    return false;
                }
            }
            LOGI("seg_page_start = %p, file_length = %d", seg_page_start, file_length);

            void *seg_addr = fake_mmap64(reinterpret_cast<void *>(seg_page_start),
                                    file_length,
                                    prot,
                                    MAP_FIXED | MAP_PRIVATE,
                                    fd_,
                                    file_offset_ + file_page_start);
            if (seg_addr == MAP_FAILED) {
                LOGE("couldn't map \"%s\" segment %zd: %s", name_.c_str(), i, strerror(errno));
                return false;
            }
            // this we set the name of the segment
            if (ENBALE_HIDE_MAP ==ON) {
                prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, seg_addr, PAGE_END(file_length), FAKE_SEGMENT_NAME);
            }
            // Mark segments as huge page eligible if they meet the requirements
            // (executable and PMD aligned).
            if ((phdr->p_flags & PF_X) && phdr->p_align == kPmdSize &&
                get_transparent_hugepages_supported()) {
                madvise(seg_addr, file_length, MADV_HUGEPAGE);
            }
            // if the segment is writable, and does not end on a page boundary,
            // zero-fill it until the page limit.
            if ((phdr->p_flags & PF_W) != 0 && PAGE_OFFSET(seg_file_end) > 0) {
                memset(reinterpret_cast<void *>(seg_file_end), 0,
                       PAGE_SIZE - PAGE_OFFSET(seg_file_end));
            }
            seg_file_end = PAGE_END(seg_file_end);
            // seg_file_end is now the first page address after the file
            // content. If seg_end is larger, we need to zero anything
            // between them. This is done by using a private anonymous
            // map for all extra pages.
            if (seg_page_end > seg_file_end) {
                size_t zeromap_size = seg_page_end - seg_file_end;
                void *zeromap = mmap64(reinterpret_cast<void *>(seg_file_end),
                                     zeromap_size,
                                     PFLAGS_TO_PROT(phdr->p_flags),
                                     MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE,
                                     -1,
                                     0);
                LOGI("zeromap = %p size %i", zeromap,zeromap_size);
                if (zeromap == MAP_FAILED) {
                    LOGE("couldn't zero fill \"%s\" gap: %s", name_.c_str(), strerror(errno));
                    return false;
                }
                prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, zeromap, zeromap_size, FAKE_MAPS_NAME);
            }
        }
    }
    return true;
}

// Ensures that our program header is actually within a loadable
// segment. This should help catch badly-formed ELF files that
// would cause the linker to crash later when trying to access it.
bool ElfReader::CheckPhdr(ElfW(Addr) loaded) {
    const ElfW(Phdr) *phdr_limit = phdr_table_ + phdr_num_;
    ElfW(Addr) loaded_end = loaded + (phdr_num_ * sizeof(ElfW(Phdr)));
    for (const ElfW(Phdr) *phdr = phdr_table_; phdr < phdr_limit; ++phdr) {
        if (phdr->p_type != PT_LOAD) {
            continue;
        }
        ElfW(Addr) seg_start = phdr->p_vaddr + load_bias_;
        ElfW(Addr) seg_end = phdr->p_filesz + seg_start;
        if (seg_start <= loaded && loaded_end <= seg_end) {
            loaded_phdr_ = reinterpret_cast<const ElfW(Phdr) *>(loaded);
            return true;
        }
    }
    LOGE("\"%s\" loaded phdr %p not in loadable segment",
         name_.c_str(), reinterpret_cast<void *>(loaded));
    return false;
}
// Sets loaded_phdr_ to the address of the program header table as it appears
// in the loaded segments in memory. This is in contrast with phdr_table_,
// which is temporary and will be released before the library is relocated.

//这段代码的目的是在动态链接过程中，为已加载的ELF文件定位程序头表（Program Header Table, PHDR）
// 的内存地址。这一步骤对于后续的库重定位和初始化至关重要。
// 在ELF文件格式中，程序头表描述了文件的段（比如代码段、数据段等）如何映射到进程的虚拟地址空间中。
// 不同于phdr_table_，这是一个临时的、在链接器内部使用的拷贝，loaded_phdr_指向的是映射到内存中、即将被实际使用的程序头表的地址。
bool ElfReader::FindPhdr() {
    const ElfW(Phdr) *phdr_limit = phdr_table_ + phdr_num_;
    // If there is a PT_PHDR, use it directly.
    // If there is a PT_PHDR, use it directly.
    for (const ElfW(Phdr) *phdr = phdr_table_; phdr < phdr_limit; ++phdr) {
        if (phdr->p_type == PT_PHDR) {
            return CheckPhdr(load_bias_ + phdr->p_vaddr);
        }
    }
    // Otherwise, check the first loadable segment. If its file offset
    // is 0, it starts with the ELF header, and we can trivially find the
    // loaded program header from it.
    for (const ElfW(Phdr) *phdr = phdr_table_; phdr < phdr_limit; ++phdr) {
        if (phdr->p_type == PT_LOAD) {
            if (phdr->p_offset == 0) {
                ElfW(Addr) elf_addr = load_bias_ + phdr->p_vaddr;
                const ElfW(Ehdr) *ehdr = reinterpret_cast<const ElfW(Ehdr) *>(elf_addr);
                ElfW(Addr) offset = ehdr->e_phoff;
                return CheckPhdr(reinterpret_cast<ElfW(Addr)>(ehdr) + offset);
            }
            break;
        }
    }

    LOGE("can't find loaded phdr for \"%s\"", name_.c_str());
    return false;
}

// Tries to find .note.gnu.property section.
// It is not considered an error if such section is missing.
bool ElfReader::FindGnuPropertySection() {
#if defined(__aarch64__)
    note_gnu_property_ = GnuPropertySection(phdr_table_, phdr_num_, load_start(), name_.c_str());
#endif
    return true;
}

/* Used internally. Used to set the protection bits of all loaded segments
 * with optional extra flags (i.e. really PROT_WRITE). Used by
 * phdr_table_protect_segments and phdr_table_unprotect_segments.
 */
static int _phdr_table_set_load_prot(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                     ElfW(Addr) load_bias, int extra_prot_flags) {
    const ElfW(Phdr)* phdr = phdr_table;
    const ElfW(Phdr)* phdr_limit = phdr + phdr_count;

    for (; phdr < phdr_limit; phdr++) {
        if (phdr->p_type != PT_LOAD || (phdr->p_flags & PF_W) != 0) {
            continue;
        }

        ElfW(Addr) seg_page_start = PAGE_START(phdr->p_vaddr) + load_bias;
        ElfW(Addr) seg_page_end   = PAGE_END(phdr->p_vaddr + phdr->p_memsz) + load_bias;

        int prot = PFLAGS_TO_PROT(phdr->p_flags) | extra_prot_flags;
        if ((prot & PROT_WRITE) != 0) {
            // make sure we're never simultaneously writable / executable
            prot &= ~PROT_EXEC;
        }
#if defined(__aarch64__)
        if ((prot & PROT_EXEC) == 0) {
            // Though it is not specified don't add PROT_BTI if segment is not
            // executable.
            prot &= ~PROT_BTI;
        }
#endif

        int ret =
                mprotect(reinterpret_cast<void*>(seg_page_start), seg_page_end - seg_page_start, prot);
        if (ret < 0) {
            return -1;
        }
    }
    return 0;
}

/* Return the address and size of the ELF file's .dynamic section in memory,
 * or null if missing.
 *
 * Input:
 *   phdr_table  -> program header table
 *   phdr_count  -> number of entries in tables
 *   load_bias   -> load bias
 * Output:
 *   dynamic       -> address of table in memory (null on failure).
 *   dynamic_flags -> protection flags for section (unset on failure)
 * Return:
 *   void
 */
void phdr_table_get_dynamic_section(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                    ElfW(Addr) load_bias, ElfW(Dyn)** dynamic,
                                    ElfW(Word)* dynamic_flags) {
    *dynamic = nullptr;
    for (size_t i = 0; i<phdr_count; ++i) {
        const ElfW(Phdr)& phdr = phdr_table[i];
        if (phdr.p_type == PT_DYNAMIC) {
            *dynamic = reinterpret_cast<ElfW(Dyn)*>(load_bias + phdr.p_vaddr);
            if (dynamic_flags) {
                *dynamic_flags = phdr.p_flags;
            }
            return;
        }
    }
}

/* Restore the original protection modes for all loadable segments.
 * You should only call this after phdr_table_unprotect_segments and
 * applying all relocations.
 *
 * AArch64: also called from linker_main and ElfReader::Load to apply
 *     PROT_BTI for loaded main so and other so-s.
 *
 * Input:
 *   phdr_table  -> program header table
 *   phdr_count  -> number of entries in tables
 *   load_bias   -> load bias
 *   prop        -> GnuPropertySection or nullptr
 * Return:
 *   0 on error, -1 on failure (error code in errno).
 */
int phdr_table_protect_segments(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                ElfW(Addr) load_bias, const GnuPropertySection* prop __unused) {
    int prot = 0;
#if defined(__aarch64__)
    if ((prop != nullptr) && prop->IsBTICompatible()) {
        prot |= PROT_BTI;
    }
#endif
    return _phdr_table_set_load_prot(phdr_table, phdr_count, load_bias, prot);
}
bool ElfReader::Load(address_space_params *address_space) {
    if (did_load_) {
        return true;
    }
    if (ReserveAddressSpace(address_space) && LoadSegments()
        && FindPhdr() && FindGnuPropertySection()) {
        did_load_ = true;
#if defined(__aarch64__)
        // For Armv8.5-A loaded executable segments may require PROT_BTI.
        LOGI("isBTICompatible = %d", note_gnu_property_.IsBTICompatible());
        if (note_gnu_property_.IsBTICompatible()) {
            did_load_ = (phdr_table_protect_segments(phdr_table_, phdr_num_, load_bias_,
                                                     &note_gnu_property_) == 0);
        }
#endif
    }
    return did_load_;
}
