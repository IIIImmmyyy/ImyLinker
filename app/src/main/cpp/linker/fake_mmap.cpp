//
// Created by PC5000 on 2024/3/29.
//

#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include "fake_mmap.h"
#include "linker.h"
#include "log.h"



void* fake_mmap64(void *addr, size_t length, int prot, int flags, int fd, off_t offset)  {
    //判断宏定义 ENBALE_HIDE_MAP 是否等于1
    if (ENBALE_HIDE_MAP ==0) {
        //判断__addr是否等于0
     return   mmap64(addr, length, prot, flags, fd, offset);
    } else{
// 验证参数

        return mmap64(addr, length, prot, flags, fd, offset);
    }
}