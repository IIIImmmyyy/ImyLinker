//
// Created by PC5000 on 2024/4/1.
//

#ifndef LINKERBRIDGE_LINKER_GLOBALS_H
#define LINKERBRIDGE_LINKER_GLOBALS_H

#include <link.h>
constexpr ElfW(Versym) kVersymNotNeeded = 0;
constexpr ElfW(Versym) kVersymGlobal = 1;
#endif //LINKERBRIDGE_LINKER_GLOBALS_H
