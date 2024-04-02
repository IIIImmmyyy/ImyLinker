#pragma once

#include <cstdio>

class FdPath {
public:
    explicit FdPath(int fd) {
        snprintf(buf, sizeof(buf), "/proc/self/fd/%d", fd);
    }

    const char* c_str() {
        return buf;
    }

private:
    char buf[40];
};