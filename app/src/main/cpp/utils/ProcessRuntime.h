//
// Created by PC5000 on 2024/3/27.
//

#ifndef LINKERBRIDGE_PROCESSRUNTIME_H
#define LINKERBRIDGE_PROCESSRUNTIME_H

#include "vector"
struct ElfModule{
    char  path[1024];
    void* address;
};
static std::vector<ElfModule> ElfModuleMap;

class ProcessRuntime {

public:
    static ElfModule GetTargetElfModule(const char* soName);
    static void GetCmdlineForPid(int pid, char *cmdlineBuffer, size_t bufferSize);

};


#endif //LINKERBRIDGE_PROCESSRUNTIME_H
