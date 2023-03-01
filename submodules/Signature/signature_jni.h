
#include <jni.h>

JNIEXPORT jbyteArray JNICALL Java_org_pniei_moduleskzi_utils_Signature_ecpform(JNIEnv *env, jobject this, jbyteArray key, jbyteArray data);
JNIEXPORT jint JNICALL Java_org_pniei_moduleskzi_utils_Signature_ecpcontrol(JNIEnv *env, jobject this, jbyteArray key, jbyteArray data, jbyteArray ecp);
JNIEXPORT jbyteArray JNICALL Java_org_pniei_moduleskzi_utils_Signature_getkeyform(JNIEnv *env, jobject this, jint numKey);
JNIEXPORT jbyteArray JNICALL Java_org_pniei_moduleskzi_utils_Signature_getkeycontrol(JNIEnv *env, jobject this, jint numKey);



