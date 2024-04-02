//
// Created by PC5000 on 2024/3/27.
//

#ifndef LINKERBRIDGE_MYLINKER_H
#define LINKERBRIDGE_MYLINKER_H
#include "linker.h"
static void* dlopen_ext(const char* filename,
                        int flags,
                        const android_dlextinfo* extinfo,
                        const void* caller_addr) {
    void* result = do_dlopen(filename, flags, extinfo, caller_addr);
    return result;
}
void* __loader_dlopen(const char* filename, int flags, const void* caller_addr) {
    return dlopen_ext(filename, flags, nullptr, caller_addr);
}
void* my_dlopen(const char* filename, int flag){
    const void* caller_addr = __builtin_return_address(0);
    return __loader_dlopen(filename, flag, caller_addr);
}

#endif //LINKERBRIDGE_MYLINKER_H
