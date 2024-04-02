#include <jni.h>
#include <string>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include "base.h"
#include <stdio.h>
#include <syscall.h>
#include "dlfcn.h"
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "elf.h"
#include "FdPath.h"
#include <unistd.h>
#include <sys/wait.h>
#include "linker/mylinker.h"
#include <stdio.h>

#define memfd_create 279

extern "C" JNIEXPORT jstring

JNICALL
Java_com_example_linkerbridge_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */) {
    std::string hello = "Hello from C++";


    return env->NewStringUTF(hello.c_str());
}

// 尝试挂载tmpfs
void mount_tmpfs(const char *mount_point) {
    if (mount("tmpfs", mount_point, "tmpfs", 0, "size=100m") == -1) {
        perror("mount tmpfs failed");
        exit(1);
    }
}

// 将.so文件复制到tmpfs中
void copy_so_to_tmpfs(const char *src_path, const char *dst_path) {
    int src_fd, dst_fd, n;
    char buf[1024];

    src_fd = open(src_path, O_RDONLY);
    if (src_fd == -1) {
        perror("open src file failed");
        exit(1);
    }

    dst_fd = open(dst_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dst_fd == -1) {
        perror("open dst file failed");
        close(src_fd);
        exit(1);
    }

    while ((n = read(src_fd, buf, sizeof(buf))) > 0) {
        if (write(dst_fd, buf, n) != n) {
            perror("write failed");
            close(src_fd);
            close(dst_fd);
            exit(1);
        }
    }

    close(src_fd);
    close(dst_fd);
}
void loadSo() {
    my_dlopen("/data/local/tmp/inject", RTLD_NOW);
}
extern "C" JNIEXPORT void
JNICALL
Java_com_example_linkerbridge_MainActivity_loadSo(
        JNIEnv *env,
        jobject /* this */) {
}

__attribute__((constructor))
void setup_ld_debug(void) {
    loadSo();

}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_linkerbridge_MainActivity_loadSo2(JNIEnv *env, jobject thiz) {
    // 使用 system 函数执行命令
    void *pVoid = dlopen("/data/local/tmp/inject", RTLD_NOW);
    LOGI(" dlopen call %p",pVoid);
    if (pVoid== nullptr){
        LOGI("dlopen error %s",dlerror());
    }

}