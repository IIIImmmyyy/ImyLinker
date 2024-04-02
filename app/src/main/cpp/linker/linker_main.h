//
// Created by PC5000 on 2024/3/27.
//

#ifndef LINKERBRIDGE_LINKER_MAIN_H
#define LINKERBRIDGE_LINKER_MAIN_H
#include "vector"
#include "../Dobby/builtin-plugin/BionicLinkerRestriction/bionic_linker_restriction.h"

struct soinfo;

soinfo* solist_get_somain();
soinfo* solist_get_head();
std::vector<soinfo_t> linker_get_solist();

#endif //LINKERBRIDGE_LINKER_MAIN_H
