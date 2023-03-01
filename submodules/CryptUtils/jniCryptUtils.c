
#include <string.h>
#include <malloc.h>

#include    "jniCryptUtils.h"
#include    "Hesh341112.h"
#include    "crc32.h"
#include    "CryptUtils.h"

#if defined(CRYPT_GOST28147)
    #include "Gost28147.h"
#elif defined(CRYPT_MAGMA)
    #include "cypher.h"

#endif

JNIEXPORT void JNICALL
Java_org_pniei_moduleskzi_utils_CryptUtils_initcryptblock(JNIEnv *env, jclass this, jbyteArray jkey) {
    unsigned char isCp;
    unsigned char * key = (*env)->GetByteArrayElements(env, jkey,  &isCp);
    unsigned int len_key = (*env)->GetArrayLength(env, jkey);
    init_key_block(key, len_key);
    (*env)->ReleaseByteArrayElements(env, jkey, key, JNI_ABORT);
}

JNIEXPORT jbyteArray JNICALL Java_org_pniei_moduleskzi_utils_CryptUtils_cryptblock(JNIEnv *env, jclass this, jbyteArray jdata, jbyteArray jsp, jint jisFirst) {
    unsigned char isCp;
    unsigned char * data, * crypted_data, * sp = NULL;
    unsigned int len_data;
    jbyteArray jcrypted_data = NULL;

    data = (*env)->GetByteArrayElements(env, jdata,  &isCp);
    len_data = (*env)->GetArrayLength(env, jdata);
    if (jsp != NULL)
        sp = (*env)->GetByteArrayElements(env, jsp,  &isCp);

    crypted_data = crypt_data_block(jisFirst, data, len_data, sp);

    if(crypted_data != NULL) {
        jcrypted_data = (*env)->NewByteArray(env, len_data);
        (*env)->SetByteArrayRegion(env, jcrypted_data, 0, len_data, crypted_data);
        free(crypted_data);
    }

    (*env)->ReleaseByteArrayElements(env, jdata, data, JNI_ABORT);
    if (jsp != NULL)
        (*env)->ReleaseByteArrayElements(env, jsp, sp, JNI_ABORT);
    return jcrypted_data;
}

JNIEXPORT jbyteArray JNICALL Java_org_pniei_moduleskzi_utils_CryptUtils_decryptblock(JNIEnv *env, jclass this, jbyteArray jdata, jbyteArray jsp, jint jisFirst) {
    unsigned char isCp;
    unsigned char * data,  * decrypted_data, * sp = NULL;
    unsigned int len_data;
    jbyteArray jdecrypted_data = NULL;

    data = (*env)->GetByteArrayElements(env, jdata,  &isCp);
    len_data = (*env)->GetArrayLength(env, jdata);
    if (jsp != NULL)
        sp = (*env)->GetByteArrayElements(env, jsp,  &isCp);

    decrypted_data = decrypt_data_block(jisFirst, data, len_data, sp);
    if(decrypted_data != NULL) {
        jdecrypted_data = (*env)->NewByteArray(env, len_data);
        (*env)->SetByteArrayRegion(env, jdecrypted_data, 0, len_data,  decrypted_data);
        free(decrypted_data);
    }

    (*env)->ReleaseByteArrayElements(env, jdata, data, JNI_ABORT);
    if (jsp != NULL)
        (*env)->ReleaseByteArrayElements(env, jsp, sp, JNI_ABORT);
    return jdecrypted_data;
}

JNIEXPORT jbyteArray JNICALL Java_org_pniei_moduleskzi_utils_CryptUtils_getizv(JNIEnv *env, jclass this) {
    unsigned char isCp;
    unsigned char * izv;
    jbyteArray jizv = NULL;

    izv = getIZV();
    if(izv != NULL) {
        jizv = (*env)->NewByteArray(env, 4);
        (*env)->SetByteArrayRegion(env, jizv, 0, 4,  izv);
    }
    return jizv;
}

JNIEXPORT void JNICALL Java_org_pniei_moduleskzi_utils_CryptUtils_initcryptsound(JNIEnv *env, jobject this, jbyteArray keyOut, jbyteArray keyIn, jint isCript) {
    jboolean isCp;
    unsigned char * jkey_out = NULL;
    unsigned char * jkey_in = NULL;

    if(keyOut != NULL && keyIn != NULL) {
        jkey_out = (*env)->GetByteArrayElements(env, keyOut, &isCp);
        jkey_in = (*env)->GetByteArrayElements(env, keyIn, &isCp);
        init_crypt_sound(jkey_out, jkey_in, (unsigned char)isCript);
        (*env)->ReleaseByteArrayElements(env, keyOut, jkey_out, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, keyIn, jkey_in, JNI_ABORT);
    } else {
        init_crypt_sound(NULL, NULL, (unsigned char)isCript);
    }
}

JNIEXPORT jbyteArray JNICALL
Java_org_pniei_moduleskzi_utils_CryptUtils_cryptdata(JNIEnv *env, jobject this, jbyteArray open_data, jbyteArray key) {
    unsigned char isCp;
    unsigned char * jopen_data, * jkey, * jcrypted_data;
    int jlen_open_data, jlen_key, jlen_crypted_data;
    jbyteArray crypted_data = NULL;

    if(open_data == NULL || key == NULL)
        return NULL;

    jopen_data = (unsigned char *)(*env)->GetByteArrayElements(env, open_data, &isCp);
    jkey = (unsigned char *)(*env)->GetByteArrayElements(env, key, &isCp);
    jlen_open_data = (*env)->GetArrayLength(env, open_data);
    jlen_key = (*env)->GetArrayLength(env, key);

    jcrypted_data = crypt_data(jopen_data, jlen_open_data, jkey, jlen_key, &jlen_crypted_data);

    if(jcrypted_data != NULL) {
        crypted_data = (*env)->NewByteArray(env, jlen_crypted_data);
        if(crypted_data == NULL)
            return NULL;
        (*env)->SetByteArrayRegion(env, crypted_data, 0, jlen_crypted_data, jcrypted_data);
        free(jcrypted_data);
    }

    (*env)->ReleaseByteArrayElements(env, open_data, jopen_data, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, key, jkey, JNI_ABORT);

    return crypted_data;
}

JNIEXPORT jbyteArray JNICALL
Java_org_pniei_moduleskzi_utils_CryptUtils_decryptdata(JNIEnv *env, jobject this, jbyteArray crypted_data, jbyteArray key){
    unsigned char isCp;
    unsigned char * jcrypted_data, * jkey, * jdata;
    int len_crypted_data, len_data, len_key;

    jbyteArray open_data = NULL;

    if(crypted_data == NULL || key == NULL)
        return NULL;

    jcrypted_data = (unsigned char *)(*env)->GetByteArrayElements(env, crypted_data, &isCp);
    jkey = (unsigned char *)(*env)->GetByteArrayElements(env, key, &isCp);
    len_crypted_data = (*env)->GetArrayLength(env, crypted_data);
    len_key = (*env)->GetArrayLength(env, key);

    jdata = decrypt_data(jcrypted_data, len_crypted_data, jkey, len_key, &len_data);

    if(jdata != NULL) {
        open_data = (*env)->NewByteArray(env, len_data);
        if(open_data == NULL)
            return NULL;
        (*env)->SetByteArrayRegion(env, open_data, 0, len_data, jdata);
        free(jdata);
    }

    (*env)->ReleaseByteArrayElements(env, crypted_data, jcrypted_data, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, key, jkey, JNI_ABORT);

    return open_data;
}

JNIEXPORT jbyteArray JNICALL
Java_org_pniei_moduleskzi_utils_CryptUtils_cryptdataneyro(JNIEnv * env, jclass this, jbyteArray jdata, jint lenData, jbyteArray jkey) {
    uint8_t isCp;
    unsigned char * data, * key, * crypted_data;
    unsigned int len_data, len_key, len_crypted_data;
    jbyteArray jcrypted_data = NULL;

    data = (*env)->GetByteArrayElements(env, jdata,  &isCp);
    len_data = lenData;
    key = (*env)->GetByteArrayElements(env, jkey, &isCp);
    len_key = (*env)->GetArrayLength(env, jkey);

    crypted_data = crypt(data, len_data, key, len_key, &len_crypted_data);

    if(crypted_data != NULL) {
        jcrypted_data = (*env)->NewByteArray(env, len_crypted_data);
        (*env)->SetByteArrayRegion(env, jcrypted_data, 0, len_crypted_data, crypted_data);
        free(crypted_data);
    }

    (*env)->ReleaseByteArrayElements(env, jdata, data, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, jkey, key, JNI_ABORT);

    return jcrypted_data;
}

JNIEXPORT jbyteArray JNICALL
Java_org_pniei_moduleskzi_utils_CryptUtils_decryptdataneyro(JNIEnv * env, jclass this, jbyteArray jdata, jint jlenData, jbyteArray jkey) {
    uint8_t isCp;
    unsigned char * data, * key, * decrypted_data;
    unsigned int len_data, len_key, len_decrypted_data;
    jbyteArray jdecrypted_data = NULL;

    data = (*env)->GetByteArrayElements(env, jdata,  &isCp);
    len_data = jlenData;
    key = (*env)->GetByteArrayElements(env, jkey, &isCp);
    len_key = (*env)->GetArrayLength(env, jkey);

    decrypted_data = decrypt(data, len_data, key, len_key, &len_decrypted_data);
    if(decrypted_data != NULL) {
        jdecrypted_data = (*env)->NewByteArray(env, len_decrypted_data);
        (*env)->SetByteArrayRegion(env, jdecrypted_data, 0, len_decrypted_data,  decrypted_data+LEN_LEN);
        free(decrypted_data);
    }

    (*env)->ReleaseByteArrayElements(env, jdata, data, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, jkey, key, JNI_ABORT);
    return jdecrypted_data;
}

JNIEXPORT jbyteArray JNICALL Java_org_pniei_moduleskzi_utils_CryptUtils_gethash(JNIEnv *env, jclass clazz,
                                                                            jbyteArray pass) {
    unsigned char isCp;
    unsigned char * jpass, * jhesh;
    int jlen_pass;
    jbyteArray hesh = NULL;

    if(pass == NULL)
        return NULL;

    jpass = (unsigned char *)(*env)->GetByteArrayElements(env, pass, &isCp);
    jlen_pass = (*env)->GetArrayLength(env, pass);

    jhesh = calculation_hash(jpass, jlen_pass);

    if(jhesh != NULL) {
        hesh = (*env)->NewByteArray(env, 32);
        if (hesh == NULL) {
            free(jhesh);
            return NULL;
        }

        (*env)->SetByteArrayRegion(env, hesh, 0, 32, jhesh);
        free(jhesh);
    }

    (*env)->ReleaseByteArrayElements(env, pass, jpass, JNI_ABORT);
    return hesh;
}

JNIEXPORT jbyteArray JNICALL
Java_org_pniei_moduleskzi_utils_CryptUtils_gethmac(JNIEnv *env, jclass clazz, jbyteArray kbuf, jbyteArray tbuf) {
    unsigned char isCp;
    unsigned char * jkbuf, * jresult, * jtbuf;
    int jlen_kbuf, jlen_tbuf;
    jbyteArray result = NULL;

    if(kbuf == NULL)
        return NULL;

    jkbuf = (unsigned char *)(*env)->GetByteArrayElements(env, kbuf, &isCp);
    jlen_kbuf = (*env)->GetArrayLength(env, kbuf);

    jtbuf = (unsigned char *)(*env)->GetByteArrayElements(env, tbuf, &isCp);
    jlen_tbuf = (*env)->GetArrayLength(env, tbuf);

    jresult = hmac512(jkbuf, jlen_kbuf, jtbuf, jlen_tbuf);

    if(jresult != NULL) {
        result = (*env)->NewByteArray(env, 64);
        if (result == NULL) {
            free(jresult);
            return NULL;
        }

        (*env)->SetByteArrayRegion(env, result, 0, 64, jresult);
        free(jresult);
    }

    (*env)->ReleaseByteArrayElements(env, kbuf, jkbuf, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, tbuf, jtbuf, JNI_ABORT);
    return result;
}

JNIEXPORT jint JNICALL
Java_org_pniei_moduleskzi_utils_CryptUtils_crc32(JNIEnv *env, jclass clazz, jbyteArray buff, jint len) {
    unsigned char isCp;
    unsigned char * jbuff;
    unsigned int crc;

    jbuff = (unsigned char *)(*env)->GetByteArrayElements(env, buff, &isCp);
    crc = crc32(jbuff, len);
    (*env)->ReleaseByteArrayElements(env, buff, jbuff, JNI_ABORT);
    return crc;
}

extern unsigned int test_magma(void);
JNIEXPORT void JNICALL
Java_org_pniei_moduleskzi_utils_CryptUtils_testmagma(JNIEnv *env, jobject this) {
    test_magma();
}