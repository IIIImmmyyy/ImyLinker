//
// Created by PC5000 on 2024/3/27.
//

#include "ProcessRuntime.h"
#include "link.h"
#define LINE_MAX 2048
// format print
#ifdef __LP64__
#define __PRI_64_prefix  "l"
#define __PRI_PTR_prefix "l"
#else
#define __PRI_64_prefix "ll"
#define __PRI_PTR_prefix
#endif
#define PRIxPTR __PRI_PTR_prefix "x" /* uintptr_t */
ElfModule ProcessRuntime::GetTargetElfModule(const char *soName) {
    ElfModule elfModule;
    if (ElfModuleMap.empty()){
        FILE *fp = fopen("/proc/self/maps", "r");
        if (fp== nullptr){
            return elfModule;
        }
        while (!feof(fp)) {
            char line_buffer[LINE_MAX + 1];
            fgets(line_buffer, LINE_MAX, fp);

            // ignore the rest of characters
            if (strlen(line_buffer) == LINE_MAX && line_buffer[LINE_MAX] != '\n') {
                // Entry not describing executable data. Skip to end of line to set up
                // reading the next entry.
                int c;
                do {
                    c = getc(fp);
                } while ((c != EOF) && (c != '\n'));
                if (c == EOF)
                    break;
            }
            uintptr_t region_start, region_end;
            uintptr_t region_offset;
            char permissions[5] = {'\0'}; // Ensure NUL-terminated string.
            uint8_t dev_major = 0;
            uint8_t dev_minor = 0;
            long inode = 0;
            int path_index = 0;

            // Sample format from man 5 proc:
            //
            // address           perms offset  dev   inode   pathname
            // 08048000-08056000 r-xp 00000000 03:0c 64593   /usr/sbin/gpm
            //
            // The final %n term captures the offset in the input string, which is used
            // to determine the path name. It *does not* increment the return value.
            // Refer to man 3 sscanf for details.
            if (sscanf(line_buffer,
                       "%" PRIxPTR "-%" PRIxPTR " %4c "
                                                "%" PRIxPTR " %hhx:%hhx %ld %n",
                    &region_start, &region_end, permissions, &region_offset, &dev_major, &dev_minor,
                    &inode,
                    &path_index) < 7) {

                fclose(fp);
                return elfModule;
            }
            // check header section permission
            if (strcmp(permissions, "r--p") != 0 && strcmp(permissions, "r-xp") != 0)
                continue;

            // check elf magic number
//        DLOG(1, "================ region_start header %i", region_start);
            if (region_start == 0) {
                continue;
            }
            char *path_buffer = line_buffer + path_index;
            if (strstr(path_buffer,"binder")!= nullptr){
                continue;
            }
            ElfW(Ehdr) *header = (ElfW(Ehdr) *) region_start;
            if (memcmp(header->e_ident, ELFMAG, SELFMAG) != 0) {
                continue;
            }

            if (*path_buffer == 0 || *path_buffer == '\n' || *path_buffer == '[')
                continue;
            ElfModule module;

            // strip
            if (path_buffer[strlen(path_buffer) - 1] == '\n') {
                path_buffer[strlen(path_buffer) - 1] = 0;
            }
            strncpy(module.path, path_buffer, sizeof(module.path));
            module.address = (void *) region_start;
            ElfModuleMap.push_back(module);
        }
    }

    for (auto module: ElfModuleMap) {
        if (strstr(module.path, soName) != 0) {
            return module;
        }
    }
    return elfModule;
}

void ProcessRuntime::GetCmdlineForPid(int pid, char *cmdlineBuffer, size_t bufferSize) {
    char path[256];
    FILE *fp;

    // 构造文件路径 /proc/[pid]/cmdline
    sprintf(path, "/proc/%d/cmdline", pid);

    // 尝试打开文件
    fp = fopen(path, "r");
    if (fp == NULL) {
        perror("Error opening file");
        return;
    }

    // 尝试读取cmdline文件的内容
    if (fgets(cmdlineBuffer, bufferSize, fp) == NULL) {
        fprintf(stderr, "Failed to read cmdline for PID %d\n", pid);
    }

    // 关闭文件
    fclose(fp);
}

