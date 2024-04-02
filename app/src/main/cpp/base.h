//
// Created by Administrator on 2021/11/16.
//
#include <android/log.h>
#include <jni.h>
#ifndef MY_APPLICATION_BASE_H
#define MY_APPLICATION_BASE_H

#define targetLibName "libil2cpp.so"

#define ENABLE true
#define LOG_TAG "Imy"
#if ENABLE
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,LOG_TAG,__VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG,__VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,LOG_TAG,__VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,LOG_TAG,__VA_ARGS__)
#else
#define LOGI(...)
#define LOGD(...)
#define LOGW(...)
#define LOGE(...)
#endif

#endif //ANDROIDCPPSOLIB_LOGUTIL_H
#ifndef DUMPER_BASE_H
#define DUMPER_BASE_H





#endif //DUMPER_BASE_H
