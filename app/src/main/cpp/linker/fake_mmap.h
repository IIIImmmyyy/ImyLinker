//
// Created by PC5000 on 2024/3/29.
//

#ifndef LINKERBRIDGE_FAKE_MMAP_H
#define LINKERBRIDGE_FAKE_MMAP_H

void* fake_mmap64(void* __addr, size_t __size, int __prot, int __flags, int __fd, off64_t __offset);


#endif //LINKERBRIDGE_FAKE_MMAP_H
