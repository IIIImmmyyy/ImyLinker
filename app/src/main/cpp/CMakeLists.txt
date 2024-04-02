# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html.
# For more examples on how to use CMake, see https://github.com/android/ndk-samples.

# Sets the minimum CMake version required for this project.
cmake_minimum_required(VERSION 3.22.1)

# Declares the project name. The project name can be accessed via ${ PROJECT_NAME},
# Since this is the top level CMakeLists.txt, the project name is also accessible
# with ${CMAKE_PROJECT_NAME} (both CMake variables are in-sync within the top level
# build script scope).
project("imytest")


#开始优化
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O")
# inline
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility-inlines-hidden")

macro(SET_OPTION option value)
    set(${option} ${value} CACHE INTERNAL "" FORCE)
endmacro()
SET_OPTION(DOBBY_DEBUG ON)
SET_OPTION(DOBBY_GENERATE_SHARED OFF)
SET_OPTION(Plugin.LinkerLoadCallback OFF)
add_subdirectory(${DobbyHome} Dobby)
set(DobbyHome Dobby)
# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.
#
# In this top level CMakeLists.txt, ${CMAKE_PROJECT_NAME} is used to define
# the target library name; in the sub-module's CMakeLists.txt, ${PROJECT_NAME}
# is preferred for the same purpose.
#
# In order to load a library into your app from Java/Kotlin, you must call
# System.loadLibrary() and pass the name of the library defined here;
# for GameActivity/NativeActivity derived applications, the same library name must be
# used in the AndroidManifest.xml file.
add_library(${CMAKE_PROJECT_NAME} SHARED
        linker/linker.cpp
        linker/linker_soinfo.cpp
        linker/linker_common_types.h
        linker/linker_mapped_file_fragment.cpp
        linker/linker_phdr.cpp
        linker/linker_note_gnu_property.cpp
        linker/linker_utils.cpp
        linker/linker_block_allocator.cpp
        linker/linker_main.cpp
        linker/linker_namespaces.cpp
        linker/linker_tls.cpp
        linker/linker_config.cpp
        linker/linker_transparent_hugepage_support.cpp
        linker/linker_relocate.cpp
        linker/linker_gun_hash.cpp
        linker/fake_mmap.cpp
        linker/private/bionic_elf_tls.cpp
        utils/FileUtils.cpp
        utils/ProcessRuntime.cpp
        # List C/C++ source files with relative paths to this CMakeLists.txt.
        native-lib.cpp)

# Specifies libraries CMake should link to your target library. You
# can link libraries from various origins, such as libraries defined in this
# build script, prebuilt third-party libraries, or Android system libraries.
target_link_libraries(${CMAKE_PROJECT_NAME}
        aaa
        # List libraries link to the target library
        android

        log)