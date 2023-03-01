#include "signature.h"
#include "signature_jni.h"
#include <string.h>
#include <malloc.h>

JNIEXPORT jbyteArray JNICALL Java_org_pniei_moduleskzi_utils_Signature_ecpform(JNIEnv *env, jobject this, jbyteArray key, jbyteArray data) {
    uint8_t isCp;
	uint8_t * _key = (*env)->GetByteArrayElements(env, key, &isCp);
    uint8_t * _data = (*env)->GetByteArrayElements(env, data, &isCp);
	int len = (*env)->GetArrayLength(env, data);
    uint8_t  * ecp;
	int len_ecp;
    uint32_t  jnierr;
	
	jnierr = ecp_form(_key, _data, len, &ecp, &len_ecp);
	(*env)->ReleaseByteArrayElements(env, data, (jbyte*)_data, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, key, (jbyte*)_key, JNI_ABORT);
	
	if (jnierr) {
		return NULL;
	} else {
		jbyteArray jecp = (*env)->NewByteArray(env, len_ecp);
		(*env)->SetByteArrayRegion(env, jecp, 0, len_ecp,  (jbyte *)ecp);
		free(ecp);
		return jecp;
	}
}

JNIEXPORT jint JNICALL Java_org_pniei_moduleskzi_utils_Signature_ecpcontrol(JNIEnv *env, jobject this, jbyteArray key, jbyteArray data, jbyteArray ecp) {
    uint8_t isCp;
	uint8_t * _key = (*env)->GetByteArrayElements(env, key, &isCp);
    uint8_t * _data = (*env)->GetByteArrayElements(env, data, &isCp);
	uint8_t * _ecp = (*env)->GetByteArrayElements(env, ecp, &isCp);
	int len = (*env)->GetArrayLength(env, data);
	int len_ecp = (*env)->GetArrayLength(env, ecp);
    uint32_t  result;
	
	result = ecp_control(_key, _data, len, _ecp, len_ecp);
	(*env)->ReleaseByteArrayElements(env, data, (jbyte*)_data, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, key, (jbyte*)_key, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, ecp, (jbyte*)_ecp, JNI_ABORT);
	
	return (jint)result;
}

JNIEXPORT jbyteArray JNICALL Java_org_pniei_moduleskzi_utils_Signature_getkeyform(JNIEnv *env, jobject this, jint numKey) {
	unsigned char * key = get_key_form(numKey);
	jbyteArray jkey = (*env)->NewByteArray(env, 14);
	(*env)->SetByteArrayRegion(env, jkey, 0, 14,  (jbyte *)key);
	free(key);
	return jkey;
}

JNIEXPORT jbyteArray JNICALL Java_org_pniei_moduleskzi_utils_Signature_getkeycontrol(JNIEnv *env, jobject this, jint numKey) {
	unsigned char * key = get_key_control(numKey);
	jbyteArray jkey = NULL;
	if (key != NULL) {
		jkey = (*env)->NewByteArray(env, 32);
		(*env)->SetByteArrayRegion(env, jkey, 0, 32,  (jbyte *)key);
		free(key);
	}

	return jkey;
}
