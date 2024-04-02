//
// Created by PC5000 on 2024/3/27.
//
#include <android/log.h>
#include <jni.h>
#ifndef LINKERBRIDGE_LOG_H
#define LINKERBRIDGE_LOG_H
#define ENABLE true
#define LOG_TAG "MyLinker"
#define LinkerTrace "LinkerTrace"
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
#define TRACE_TYPE(...) __android_log_print(ANDROID_LOG_ERROR,LinkerTrace,__VA_ARGS__)
#endif //LINKERBRIDGE_LOG_H
