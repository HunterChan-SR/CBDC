#include <jni.h>
#include <string>
#include "libgnark.h"
#include "../jniLibs/arm64-v8a/libgnark.h"
#include "../jniLibs/x86_64/libgnark.h"

extern "C" JNIEXPORT jstring

JNICALL
Java_com_example_cdbcapp_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}
extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_cdbcapp_libnative_libnative_stringFromJNI(JNIEnv *env, jobject thiz) {
    // TODO: implement stringFromJNI()
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}
//extern "C"
//JNIEXPORT jstring JNICALL
//Java_com_example_cdbcapp_libnative_libnative_TestEnroll(JNIEnv *env, jclass clazz) {
//    // TODO: implement TestEnroll()
//    return env->NewStringUTF(TestEnroll());
//}
//extern "C"
//JNIEXPORT jstring JNICALL
//Java_com_example_cdbcapp_libnative_libnative_TestOfflineTx(JNIEnv *env, jclass clazz) {
//    // TODO: implement TestOfflineTx()
//    return env->NewStringUTF(TestOfflineTx());
//}
extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_cdbcapp_libnative_libnative_goCBDC(JNIEnv *env, jclass clazz) {
    // TODO: implement TestOfflineTx()
    return env->NewStringUTF(GO_CBDC());
}