//
// Created by PC5000 on 2024/3/27.
//

#include "linker_main.h"
#include "linker_soinfo.h"
#include "dobby.h"
#include <sys/system_properties.h>
#include "log.h"
#include "sys/auxv.h"
static int get_android_system_version() {
    char os_version_str[PROP_VALUE_MAX + 1];
    __system_property_get("ro.build.version.release", os_version_str);
    int os_version_int = atoi(os_version_str);
    return os_version_int;
}


static char *get_android_linker_path() {
#if __LP64__
    if (get_android_system_version() >= 10) {
        return "/apex/com.android.runtime/bin/linker64";
    } else {
        return "/system/bin/linker64";
    }
#else
    if (get_android_system_version() >= 10) {
    return "/apex/com.android.runtime/bin/linker";
  } else {
    return "/system/bin/linker";
  }
#endif
}


soinfo *solist_get_head() {
    soinfo *solist;
    static soinfo *(*solist_get_head)() = NULL;
    if (!solist_get_head)
        solist_get_head =
                (soinfo *(*)()) DobbySymbolResolver(get_android_linker_path(),
                                                    "__dl__Z15solist_get_headv");
    solist = (soinfo *) solist_get_head();

    return solist;
}

soinfo *solist_get_somain() {
    static soinfo *(*solist_get_head)() = NULL;
    if (!solist_get_head)
        solist_get_head =
                (soinfo *(*)()) DobbySymbolResolver(get_android_linker_path(),
                                                    "__dl__Z15solist_get_headv");
    LOGI("got soinfo head fun %p ", solist_get_head);
    return nullptr;
}