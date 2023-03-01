

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

JNIEXPORT void JNICALL
Java_org_pniei_moduleskzi_utils_CryptUtils_initcryptblock(JNIEnv *, jclass, jbyteArray);

JNIEXPORT jbyteArray JNICALL
Java_org_pniei_moduleskzi_utils_CryptUtils_cryptblock(JNIEnv *, jclass, jbyteArray, jbyteArray, jint);

JNIEXPORT jbyteArray JNICALL
Java_org_pniei_moduleskzi_utils_CryptUtils_decryptblock(JNIEnv *, jclass, jbyteArray, jbyteArray, jint);

JNIEXPORT jbyteArray JNICALL
Java_org_pniei_moduleskzi_utils_CryptUtils_getizv(JNIEnv *, jclass);

JNIEXPORT void JNICALL
Java_org_pniei_moduleskzi_utils_CryptUtils_initcryptsound(JNIEnv *env, jobject this, jbyteArray keyOut, jbyteArray keyIn, jint isCript);

JNIEXPORT jbyteArray JNICALL
Java_org_pniei_moduleskzi_utils_CryptUtils_cryptdata(JNIEnv *env, jobject this, jbyteArray data, jbyteArray key);

JNIEXPORT jbyteArray JNICALL
Java_org_pniei_moduleskzi_utils_CryptUtils_decryptdata(JNIEnv *env, jobject this, jbyteArray data, jbyteArray key);

JNIEXPORT jbyteArray JNICALL
Java_org_pniei_moduleskzi_utils_CryptUtils_cryptdataneyro(JNIEnv *, jclass, jbyteArray, jint, jbyteArray);

JNIEXPORT jbyteArray JNICALL
Java_org_pniei_moduleskzi_utils_CryptUtils_decryptdataneyro(JNIEnv *, jclass, jbyteArray, jint, jbyteArray);

JNIEXPORT jbyteArray JNICALL
Java_org_pniei_moduleskzi_utils_CryptUtils_gethash(JNIEnv *env, jclass clazz, jbyteArray pass);

JNIEXPORT jbyteArray JNICALL
Java_org_pniei_moduleskzi_utils_CryptUtils_gethmac(JNIEnv *env, jclass clazz, jbyteArray kbuf, jbyteArray tbuf);

JNIEXPORT jint JNICALL
Java_org_pniei_moduleskzi_utils_CryptUtils_crc32(JNIEnv *env, jclass clazz, jbyteArray buff, jint len);

#ifdef __cplusplus
}
#endif