
#pragma once
#if defined(__LP64__)
static constexpr const char* kLibPath = "lib64";
#else
static constexpr const char* kLibPath = "lib";
#endif