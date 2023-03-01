
#include <string.h>

#include    "jniVnpClient.h"
//#include    "Hesh341112.h"
#include    "crc32.h"
#include    "IKEv2_Def.h"
#include    "skn.h"
#include    "key.h"
#include    "test_updsch.h"

#if defined(CRYPT_GOST28147)
    #include "Gost28147.h"
#elif defined(CRYPT_MAGMA)
    #include "cypher.h"
#endif

#include "IKEv2.h"
#include "ESP.h"
#include "MMT.h"

unsigned char * DATA_IN = NULL;

JNIEXPORT void JNICALL Java_org_pniei_portal_vpn_VpnClient_ikev2init(JNIEnv *env, jobject this,
                                                                    jshort netNumber, jint lanPort, jbyteArray lanIPAdr,
                                                                    jshort serverNetNumber, jint wanPort, jbyteArray wanIPAdr,
                                                                    jbyteArray nameKompl, jbyteArray numSerial, jshort numKompl,
                                                                    jshort numOfKeys, jint random, jbyteArray tz, jbyteArray keyDsch) {
    unsigned char isCp;
    unsigned char * jlanIPAdr   = (unsigned char *)(*env)->GetByteArrayElements(env, lanIPAdr, &isCp);
    unsigned char * jwanIPAdr   = (unsigned char *)(*env)->GetByteArrayElements(env, wanIPAdr, &isCp);
    unsigned char * jnameKompl  = (unsigned char *)(*env)->GetByteArrayElements(env, nameKompl, &isCp);
    unsigned char * jtz         = (unsigned char *)(*env)->GetByteArrayElements(env, tz, &isCp);
    unsigned char * jkeyDsch  = (unsigned char *)(*env)->GetByteArrayElements(env, keyDsch, &isCp);
    unsigned char NameKompl [8];
    unsigned char NumSerial [8];
    unsigned char * jnumSerial;
    int lenNameBlock, lenNumSerial;

    lenNameBlock = (*env)->GetArrayLength(env, nameKompl);
    lenNumSerial = (*env)->GetArrayLength(env, numSerial);

    memset(NameKompl, 0, 8);
    memcpy(NameKompl, jnameKompl, lenNameBlock);

    jnumSerial  = (unsigned char *)(*env)->GetByteArrayElements(env, numSerial, &isCp);
    memset(NumSerial, 0, 8);
    memcpy(NumSerial, jnumSerial, lenNumSerial);

    if (DATA_IN != NULL)
        free(DATA_IN);
    DATA_IN = (unsigned char *) malloc(4500);

    ikev2_sa_init(netNumber, lanPort, jlanIPAdr, serverNetNumber, wanPort, jwanIPAdr, NameKompl, NumSerial, numKompl, numOfKeys, random, jtz, jkeyDsch);
    (*env)->ReleaseByteArrayElements(env, lanIPAdr, jlanIPAdr, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, wanIPAdr, jwanIPAdr, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, nameKompl, jnameKompl, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, numSerial, jnumSerial, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, tz, jtz, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, keyDsch, jkeyDsch, JNI_ABORT);
}

JNIEXPORT jbyteArray JNICALL Java_org_pniei_portal_vpn_VpnClient_ikev2getikesainit(JNIEnv *env, jobject this, jintArray  lenData) {
    unsigned char isCp;
    int * jnilenData = (*env)->GetIntArrayElements(env, lenData,  &isCp);
    unsigned char * data = NULL;
    IKEv2_STRUCT_SA * ikev2_sa;
    for(int i = 0; i < 2; i++) {
        if(ikev2_sa_pull[i].ikev2_sa != NULL) {
            if(ikev2_sa_pull[i].ikev2_sa->stage == IKE_STAGE_0) {
                ikev2_sa = ikev2_sa_pull[i].ikev2_sa;
                break;
            }
        }
    }

    pthread_mutex_lock(&ikev2_sa_mutex);
    ikev2_get_ike_sa_init(&data, jnilenData, ikev2_sa);
    pthread_mutex_unlock(&ikev2_sa_mutex);

    jbyteArray jniData = (*env)->NewByteArray(env, *jnilenData);
    (*env)->SetByteArrayRegion(env, jniData, 0, *jnilenData,  data);
    (*env)->SetIntArrayRegion(env, lenData, 0, 1,  jnilenData);
    if (data != NULL)
        free(data);
    (*env)->ReleaseIntArrayElements(env, lenData, jnilenData, JNI_ABORT);
    return jniData;
}

JNIEXPORT void JNICALL Java_org_pniei_portal_vpn_VpnClient_vpnprocessingdata(JNIEnv *env, jobject this, jbyteArray dataIn, jint lenDataIn, jbyteArray dataOut, jintArray lenDataOut, jintArray target, jintArray err) {
    unsigned char isCp;
    unsigned char * dataout = NULL;
    int  jniLenDataOut, jniTarget;
    int  jniErr;

//    datain  = (unsigned char *)(*env)->GetByteArrayElements(env, dataIn, &isCp);

    (*env)->GetByteArrayRegion(env, dataIn, 0, lenDataIn, DATA_IN);

    //vpnSetJNI(env, (*env)->NewLocalRef(env, this));
    vpnSetJNI(env);
    jniErr = vpnProcessingData(DATA_IN, lenDataIn, &dataout, &jniLenDataOut, &jniTarget);

    if(jniErr == 0 && dataout != NULL) {
        if (jniTarget != 0) {
            (*env)->SetByteArrayRegion(env, dataOut, 0, jniLenDataOut, dataout);
        }
    }

    (*env)->SetIntArrayRegion(env, target, 0, 1, &jniTarget);
    (*env)->SetIntArrayRegion(env, lenDataOut, 0, 1, &jniLenDataOut);
    (*env)->SetIntArrayRegion(env, err, 0, 1, &jniErr);
//    (*env)->ReleaseByteArrayElements(env, dataIn, datain, JNI_ABORT);
}

JNIEXPORT jint JNICALL Java_org_pniei_portal_vpn_VpnClient_getikev2stage(JNIEnv *env, jobject this){
    return get_ikev2_stage();
}

JNIEXPORT jint JNICALL Java_org_pniei_portal_vpn_VpnClient_getikev2ipaddr(JNIEnv *env, jobject this){
    return get_ikev2_ip_addr();
}

JNIEXPORT jint JNICALL Java_org_pniei_portal_vpn_VpnClient_getikev2ipmask(JNIEnv *env, jobject this){
    return get_ikev2_ip_mask();
}

JNIEXPORT jint JNICALL Java_org_pniei_portal_vpn_VpnClient_checktimesa(JNIEnv *env, jobject this){
    return ikev2_check_time_sa();
}

JNIEXPORT jint JNICALL Java_org_pniei_portal_vpn_VpnClient_espencapsuldata(JNIEnv *env, jobject this, jbyteArray dataIn, jbyteArray dataOut, jint lenDataIn, jintArray lenDataOut){
    unsigned char isCp;
    unsigned char * dataout = NULL;
    int jniLenDataOut, result;

    if (lenDataIn > 4500)
        return 1;

    (*env)->GetByteArrayRegion(env, dataIn, 0, lenDataIn, DATA_IN);
    pthread_mutex_lock(&ikev2_sa_mutex_encapsul_data);
    result = esp_encapsul_data(DATA_IN, lenDataIn, &dataout, &jniLenDataOut);
    pthread_mutex_unlock(&ikev2_sa_mutex_encapsul_data);

    if(!result) {
        (*env)->SetByteArrayRegion(env, dataOut, 0, jniLenDataOut, dataout);
        if (dataout != NULL)
            free(dataout);
    }

    (*env)->SetIntArrayRegion(env, lenDataOut, 0, 1, &jniLenDataOut);

    return result;
}

JNIEXPORT jint JNICALL Java_org_pniei_portal_vpn_VpnClient_packetforanothernetwork(JNIEnv *env, jobject this,  jbyteArray dataIn, jint lenData, jbyteArray dataOut, jintArray lenProcData) {
    unsigned char isCp;
    unsigned char * datain = (unsigned char *)(*env)->GetByteArrayElements(env, dataIn, &isCp);
    int  jnilenProcData;// = (*env)->GetIntArrayElements(env, lenProcData, &isCp);
    unsigned char * dataout = NULL;
    int result;

    result = proc_pack_for_another_network(datain, lenData, &dataout, &jnilenProcData);

    if(!result) {
        (*env)->SetByteArrayRegion(env, dataOut, 0, jnilenProcData,  dataout);
        (*env)->SetIntArrayRegion(env, lenProcData, 0, 1,  &jnilenProcData);
        if(dataout != NULL)
            free(dataout);
    }
    (*env)->ReleaseByteArrayElements(env, dataIn, datain, JNI_ABORT);
    //(*env)->ReleaseIntArrayElements(env, lenProcData, jnilenProcData, JNI_ABORT);
    return result;
}

JNIEXPORT jint JNICALL Java_org_pniei_portal_vpn_VpnClient_ikev2checkadditionalsa(JNIEnv *env, jobject this, jbyteArray dataOut, jintArray lenProcData) {
    unsigned char isCp;
    int  * jnilenProcData = (*env)->GetIntArrayElements(env, lenProcData, &isCp);
    unsigned char * dataout = NULL;
    int result;

    result = check_ikev2_sa_a(&dataout, jnilenProcData);
    if(!result) {
        (*env)->SetByteArrayRegion(env, dataOut, 0, *jnilenProcData,  dataout);
    }

    if(dataout != NULL)
        free(dataout);
    (*env)->SetIntArrayRegion(env, lenProcData, 0, 1,  jnilenProcData);
    (*env)->ReleaseIntArrayElements(env, lenProcData, jnilenProcData, JNI_ABORT);
    return result;
}

JNIEXPORT void JNICALL Java_org_pniei_portal_vpn_VpnClient_ikev2getkeepalive(JNIEnv *env, jobject this, jbyteArray dataOut, jintArray lenProcData) {
    unsigned char isCp;
    int jnilenProcData;
    unsigned char * dataout = NULL;

    vpnGetKeepalive(&dataout, &jnilenProcData);
    if(dataout != NULL) {
        (*env)->SetByteArrayRegion(env, dataOut, 0, jnilenProcData,  dataout);
        free(dataout);
    }

    (*env)->SetIntArrayRegion(env, lenProcData, 0, 1,  &jnilenProcData);
}


JNIEXPORT void JNICALL Java_org_pniei_portal_vpn_VpnClient_ikev2getdelete(JNIEnv *env, jobject this, jbyteArray dataOut, jintArray lenProcData) {
    unsigned char isCp;
    int jnilenProcData;
    unsigned char * dataout = NULL;

    vpnGetIkeDelete(&dataout, &jnilenProcData);
    if(dataout != NULL) {
        (*env)->SetByteArrayRegion(env, dataOut, 0, jnilenProcData,  dataout);
        free(dataout);
    }

    (*env)->SetIntArrayRegion(env, lenProcData, 0, 1,  &jnilenProcData);
}

JNIEXPORT void JNICALL Java_org_pniei_portal_vpn_VpnClient_ikev2getnetworksettings(JNIEnv *env, jobject this, jbyteArray dataOut, jintArray lenProcData) {
    unsigned char isCp;
    int  * jnilenProcData = (*env)->GetIntArrayElements(env, lenProcData, &isCp);
    unsigned char * dataout = NULL;

    ikev2_get_network_settings(&dataout, jnilenProcData);
    if(dataout != NULL) {
        (*env)->SetByteArrayRegion(env, dataOut, 0, *jnilenProcData,  dataout);
        free(dataout);
    }

    (*env)->SetIntArrayRegion(env, lenProcData, 0, 1,  jnilenProcData);
    (*env)->ReleaseIntArrayElements(env, lenProcData, jnilenProcData, JNI_ABORT);
}


JNIEXPORT void JNICALL Java_org_pniei_portal_vpn_VpnClient_ikev2getikedelete(JNIEnv *env, jobject this, jbyteArray dataOut, jintArray lenProcData) {
    unsigned char isCp;
    int  * jnilenProcData = (*env)->GetIntArrayElements(env, lenProcData, &isCp);

    unsigned char * dataout = NULL;
    vpnGetIkeDelete(&dataout, jnilenProcData);
    if(dataout != NULL) {
        *jnilenProcData = *jnilenProcData + 4;
        (*env)->SetByteArrayRegion(env, dataOut, 0, *jnilenProcData,  dataout);
        free(dataout);
    }

    (*env)->SetIntArrayRegion(env, lenProcData, 0, 1,  jnilenProcData);
    (*env)->ReleaseIntArrayElements(env, lenProcData, jnilenProcData, JNI_ABORT);
}

JNIEXPORT jboolean JNICALL Java_org_pniei_portal_vpn_VpnClient_isNAT(JNIEnv *env, jobject this) {
    return (jboolean)vpnIsNat();
}

JNIEXPORT void JNICALL Java_org_pniei_portal_vpn_VpnClient_ikev2clear(JNIEnv *env, jobject this) {
    vpnClear(env);
    if (DATA_IN != NULL)
        free(DATA_IN);
    DATA_IN = NULL;
}
/*
JNIEXPORT jint JNICALL Java_org_pniei_portal_vpn_VpnClient_crc32(JNIEnv *env, jobject this, jbyteArray buf, jint lenBuf){
    unsigned char isCp;
    unsigned int crc;
    unsigned char * jbuf = (unsigned char *)(*env)->GetByteArrayElements(env, buf, &isCp);

    crc = vpnCrc(jbuf, lenBuf);
    (*env)->ReleaseByteArrayElements(env, buf, jbuf, JNI_ABORT);
    return crc;
}
*/


JNIEXPORT jbyteArray JNICALL Java_org_pniei_portal_vpn_VpnClient_decryptkomplkeys(JNIEnv *env, jobject this, jbyteArray crypted_data_ki) {
    unsigned char isCp;
    unsigned char * jcrypted_data_ki, * jopen_data_ki;
    int jlen_data_ki;
    jbyteArray open_data_ki = NULL;

    jcrypted_data_ki = (unsigned char *)(*env)->GetByteArrayElements(env, crypted_data_ki, &isCp);
    jlen_data_ki = (*env)->GetArrayLength(env, crypted_data_ki);

    jopen_data_ki = decrypt_kompl_keys(jcrypted_data_ki, jlen_data_ki);

    if(jopen_data_ki != NULL) {
        open_data_ki = (*env)->NewByteArray(env, jlen_data_ki);
        if(open_data_ki == NULL)
            return NULL;
        (*env)->SetByteArrayRegion(env, open_data_ki, 0, jlen_data_ki, jopen_data_ki);
    }

    (*env)->ReleaseByteArrayElements(env, crypted_data_ki, jcrypted_data_ki, JNI_ABORT);

    return open_data_ki;
}

/*
 * Зашифровывает ключевые данные
 * buf - массив содержащий объединеные файлы с ключами (KI.M и KI.C предварительно зашифрованы в соответствии со структурой)
 * в результате работы функции будет содержать зашифрованные файлы с ключами и ИМЗ 4 байта
 * pass - массив содержащий пароль
 */
JNIEXPORT jbyteArray JNICALL Java_org_pniei_portal_vpn_VpnClient_cryptdata(JNIEnv *env, jobject this,
                                                                      jbyteArray open_data_ki,
                                                                      jbyteArray key) {
    unsigned char isCp;
    unsigned char * jopen_data_ki, * jkey, * jcrypted_data_ki;
    int jlen_open_data_ki, jlen_key, jlen_crypted_data_ki;
    jbyteArray data_ki_crypted = NULL;

    if(open_data_ki == NULL || key == NULL)
        return NULL;

    jopen_data_ki = (unsigned char *)(*env)->GetByteArrayElements(env, open_data_ki, &isCp);
    jkey = (unsigned char *)(*env)->GetByteArrayElements(env, key, &isCp);
    jlen_open_data_ki = (*env)->GetArrayLength(env, open_data_ki);
    jlen_key = (*env)->GetArrayLength(env, key);


    jcrypted_data_ki = crypt_data(jopen_data_ki, jlen_open_data_ki, jkey, jlen_key, &jlen_crypted_data_ki);


    if(jcrypted_data_ki != NULL) {
        data_ki_crypted = (*env)->NewByteArray(env, jlen_crypted_data_ki);
        if(data_ki_crypted == NULL)
            return NULL;
        (*env)->SetByteArrayRegion(env, data_ki_crypted, 0, jlen_crypted_data_ki, jcrypted_data_ki);
        free(jcrypted_data_ki);
    }

    (*env)->ReleaseByteArrayElements(env, open_data_ki, jopen_data_ki, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, key, jkey, JNI_ABORT);

    return data_ki_crypted;
}

JNIEXPORT jbyteArray JNICALL
Java_org_pniei_portal_vpn_VpnClient_decryptdata(JNIEnv *env, jobject this,
                                           jbyteArray crypted_data,
                                           jbyteArray key) {
    unsigned char isCp;
    unsigned char * jcrypted_data, * jkey, * jdata;
    int len_crypted_data, len_data, len_key;

    jbyteArray data = NULL;

    if(crypted_data == NULL || key == NULL)
        return NULL;

    jcrypted_data = (unsigned char *)(*env)->GetByteArrayElements(env, crypted_data, &isCp);
    jkey = (unsigned char *)(*env)->GetByteArrayElements(env, key, &isCp);
    len_crypted_data = (*env)->GetArrayLength(env, crypted_data);
    len_key = (*env)->GetArrayLength(env, key);

    jdata = decrypt_data(jcrypted_data, len_crypted_data, jkey, len_key, &len_data);

    if(jdata != NULL) {
        data = (*env)->NewByteArray(env, len_data);
        if(data == NULL)
            return NULL;
        (*env)->SetByteArrayRegion(env, data, 0, len_data, jdata);
        free(jdata);
    }

    (*env)->ReleaseByteArrayElements(env, crypted_data, jcrypted_data, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, key, jkey, JNI_ABORT);

    return data;
}

extern unsigned int test_magma(void);
JNIEXPORT void JNICALL Java_org_pniei_portal_vpn_VpnClient_testmagma(JNIEnv *env, jobject this) {
	test_magma();
}

JNIEXPORT void JNICALL Java_org_pniei_portal_vpn_VpnClient_testupdsch(JNIEnv *env, jobject this) {
    //test_updsch();
}

JNIEXPORT void JNICALL 
Java_org_pniei_portal_vpn_VpnClient_setsknkeys(JNIEnv *env, jobject this, jbyteArray data) {
    unsigned char isCp;
	unsigned char * jdata;
	int jlen_data;

    if(data == NULL)
        return;
	
	jdata = (unsigned char *)(*env)->GetByteArrayElements(env, data, &isCp);	
	jlen_data = (*env)->GetArrayLength(env, data);

    set_skn_keys(jdata, jlen_data);

	(*env)->ReleaseByteArrayElements(env, data, jdata, JNI_ABORT);
}

JNIEXPORT jbyteArray JNICALL
Java_org_pniei_portal_vpn_VpnClient_checkkeybyskn(JNIEnv *env, jobject this, jbyteArray keyData) {
    unsigned char isCp;
    unsigned char * jkey_data, * jnew_keys;
    int jlen_key_data, jlen_new_keys;
    jbyteArray data = NULL;

    if(keyData == NULL)
        return NULL;

    jkey_data = (unsigned char *)(*env)->GetByteArrayElements(env, keyData, &isCp);
    jlen_key_data = (*env)->GetArrayLength(env, keyData);

    jnew_keys = check_key_for_skn(jkey_data, jlen_key_data, &jlen_new_keys);

    if(jnew_keys != NULL) {
        data = (*env)->NewByteArray(env, jlen_new_keys);
        if (data == NULL)
            return NULL;

        (*env)->SetByteArrayRegion(env, data, 0, jlen_new_keys, jnew_keys);
        free(jnew_keys);
    }
    else {
        data = keyData;
    }
    (*env)->ReleaseByteArrayElements(env, keyData, jkey_data, JNI_ABORT);

    return data;
}

JNIEXPORT jbyteArray JNICALL
Java_org_pniei_portal_vpn_VpnClient_setnextkeyaswork(JNIEnv *env, jobject this, jbyteArray keyData, jbyteArray nextKey) {
    unsigned char isCp;
    unsigned char * jkey_data, * jnext_key, *jdata;
    int jlen_key_data, jlen_next_keys, jlen_data;
    jbyteArray data = NULL;

    if(keyData == NULL || nextKey == NULL)
        return NULL;

    jkey_data = (unsigned char *)(*env)->GetByteArrayElements(env, keyData, &isCp);
    jlen_key_data = (*env)->GetArrayLength(env, keyData);
    jnext_key = (unsigned char *)(*env)->GetByteArrayElements(env, nextKey, &isCp);
    jlen_next_keys = (*env)->GetArrayLength(env, nextKey);

    jdata = set_next_key_as_work(jkey_data, jlen_key_data, jnext_key, jlen_next_keys, &jlen_data);

    if(jdata != NULL) {
        data = (*env)->NewByteArray(env, jlen_data);
        if (data == NULL)
            return NULL;

        (*env)->SetByteArrayRegion(env, data, 0, jlen_data, jdata);
        free(jdata);
    }
    else {
        data = keyData;
    }

    (*env)->ReleaseByteArrayElements(env, keyData, jkey_data, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, nextKey, jnext_key, JNI_ABORT);
    return data;
}

JNIEXPORT jbyte JNICALL
Java_org_pniei_portal_vpn_VpnClient_checkkeywithskn(JNIEnv *env, jobject this,
                                        jbyteArray name,
                                        jbyteArray serial,
										jshort kompl) {
    unsigned char isCp;
	unsigned char * jname, * jserial, result;
	int jlen_name, jlen_serial;

    if(name == NULL || serial == NULL)
        return 1;
	
    jname = (unsigned char *)(*env)->GetByteArrayElements(env, name, &isCp);	
	jlen_name = (*env)->GetArrayLength(env, name);
	jserial = (unsigned char *)(*env)->GetByteArrayElements(env, serial, &isCp);	
	jlen_serial = (*env)->GetArrayLength(env, serial);
	
	result = check_key(jname, jlen_name, jserial, jlen_serial, kompl);
	
	(*env)->ReleaseByteArrayElements(env, name, jname, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, serial, jserial, JNI_ABORT);
	
	return result;
}

JNIEXPORT jbyteArray JNICALL
Java_org_pniei_portal_vpn_VpnClient_checkkeybydate(JNIEnv *env, jobject this, jbyteArray data_ki, jbyteArray now_date) {
    unsigned char isCp;
    unsigned char * jdata_ki, * jnow_date;
   int jlen_data_ki, jlen_now_date, jlen_new_key_data;
    unsigned char * jnew_key_data;
    jbyteArray new_key_data = NULL;

    if(data_ki == NULL || now_date == NULL)
        return 1;

    jdata_ki = (unsigned char *)(*env)->GetByteArrayElements(env, data_ki, &isCp);
    jlen_data_ki = (*env)->GetArrayLength(env, data_ki);
    jnow_date = (unsigned char *)(*env)->GetByteArrayElements(env, now_date, &isCp);
    jlen_now_date = (*env)->GetArrayLength(env, now_date);

    jnew_key_data = check_key_date(jdata_ki, jlen_data_ki, jnow_date, jlen_now_date, &jlen_new_key_data);

    if(jnew_key_data != NULL) {
        new_key_data = (*env)->NewByteArray(env, jlen_new_key_data);
        if (new_key_data == NULL)
            return NULL;

        (*env)->SetByteArrayRegion(env, new_key_data, 0, jlen_new_key_data, jnew_key_data);
        free(jnew_key_data);
    }
    else {
        new_key_data = data_ki;
    }

    (*env)->ReleaseByteArrayElements(env, data_ki, jdata_ki, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, now_date, jnow_date, JNI_ABORT);

    return new_key_data;
}

JNIEXPORT jint JNICALL
Java_org_pniei_portal_vpn_VpnClient_getcrcsknkeys(JNIEnv *env, jobject this) {
    return get_crc_skn_keys();
}

JNIEXPORT jbyteArray JNICALL
Java_org_pniei_portal_vpn_VpnClient_searchanddeletekey(JNIEnv *env, jobject this, jbyteArray key_delete, jbyteArray keys){
    unsigned char isCp;
    unsigned char * jkey_delete, * jkeys, * jnew_keys;
    int jlen_key_delete, jlen_keys, jlen_new_keys;
    jbyteArray data = NULL;

    if(key_delete == NULL || keys == NULL)
        return NULL;

    jkey_delete = (unsigned char *)(*env)->GetByteArrayElements(env, key_delete, &isCp);
    jlen_key_delete = (*env)->GetArrayLength(env, key_delete);
    jkeys = (unsigned char *)(*env)->GetByteArrayElements(env, keys, &isCp);
    jlen_keys = (*env)->GetArrayLength(env, keys);

    jnew_keys = search_and_delete_key(jkey_delete, jlen_key_delete, jkeys, jlen_keys, &jlen_new_keys);

    if(jnew_keys != NULL) {
        data = (*env)->NewByteArray(env, jlen_new_keys);
        if (data == NULL)
            return NULL;

        (*env)->SetByteArrayRegion(env, data, 0, jlen_new_keys, jnew_keys);
        free(jnew_keys);
    }
    else {
        data = keys;
    }

    (*env)->ReleaseByteArrayElements(env, key_delete, jkey_delete, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, keys, jkeys, JNI_ABORT);

    return data;
}

JNIEXPORT jbyteArray JNICALL
Java_org_pniei_portal_vpn_VpnClient_searchandeditkey(JNIEnv *env, jobject this, jbyteArray key_edit, jbyteArray keys) {
    unsigned char isCp;
    unsigned char * jkey_edit, * jkeys, * jnew_keys;
    int jlen_key_edit, jlen_keys;
    jbyteArray new_keys = NULL;

    if(key_edit == NULL || keys == NULL)
        return NULL;

    jkey_edit = (unsigned char *)(*env)->GetByteArrayElements(env, key_edit, &isCp);
    jlen_key_edit = (*env)->GetArrayLength(env, key_edit);
    jkeys = (unsigned char *)(*env)->GetByteArrayElements(env, keys, &isCp);
    jlen_keys = (*env)->GetArrayLength(env, keys);

    jnew_keys = search_and_edit_key(jkey_edit, jlen_key_edit, jkeys, jlen_keys);

    if(jnew_keys != NULL) {
        new_keys = (*env)->NewByteArray(env, jlen_keys);
        if (new_keys == NULL)
            return NULL;

        (*env)->SetByteArrayRegion(env, new_keys, 0, jlen_keys, jnew_keys);
    }

    (*env)->ReleaseByteArrayElements(env, key_edit, jkey_edit, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, keys, jkeys, JNI_ABORT);

    return new_keys;
}

JNIEXPORT jbyteArray JNICALL
Java_org_pniei_portal_vpn_VpnClient_addkey(JNIEnv *env, jobject this, jbyteArray key_add, jbyteArray key_data, jbyteArray keys){
    unsigned char isCp;
    unsigned char * jkey_add, * jkeys, * jnew_keys, *jkey_data;
    int jlen_key_add, jlen_keys, jlen_new_keys, jlen_key_data;
    jbyteArray data = NULL;

    if(key_data == NULL || keys == NULL)
        return NULL;


    jkey_add = (unsigned char *)(*env)->GetByteArrayElements(env, key_add, &isCp);
    jlen_key_add = (*env)->GetArrayLength(env, key_add);
    jkey_data = (unsigned char *)(*env)->GetByteArrayElements(env, key_data, &isCp);
    jlen_key_data = (*env)->GetArrayLength(env, key_data);
    jkeys = (unsigned char *)(*env)->GetByteArrayElements(env, keys, &isCp);
    jlen_keys = (*env)->GetArrayLength(env, keys);

    jnew_keys = add_key(jkey_add, jlen_key_add, jkey_data, jlen_key_data, jkeys, jlen_keys, &jlen_new_keys);

    if(jnew_keys != NULL) {
        data = (*env)->NewByteArray(env, jlen_new_keys);
        if (data == NULL)
            return NULL;

        (*env)->SetByteArrayRegion(env, data, 0, jlen_new_keys, jnew_keys);
        free(jnew_keys);
    }

    (*env)->ReleaseByteArrayElements(env, key_add, jkey_add, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, keys, jkeys, JNI_ABORT);

    return data;
}
/*
JNIEXPORT jbyteArray JNICALL Java_org_pniei_portal_vpn_VpnClient_testspeed(JNIEnv *env, jobject this, jbyteArray data_ki, jbyteArray pass) {
    unsigned char isCp;
    unsigned char * jdata_ki, * jpass, * jdata_ki_crypted, *jtemp_buf, *buffer;
    int len_data_ki, len_pass, jlen_data_ki_crypted, num0 = 0;
    unsigned int key[8];
    unsigned char imz[4];
    unsigned char sp[] = {0xfa, 0x3c, 0x9b, 0xe3, 0xa3, 0xf7, 0x87, 0xde};
    jbyteArray data_ki_crypted;

    if(data_ki == NULL || pass == NULL)
        return NULL;

    len_data_ki = (*env)->GetArrayLength(env, data_ki);
    len_pass = (*env)->GetArrayLength(env, pass);

    //jdata_ki = (unsigned char *)(*env)->GetByteArrayElements(env, data_ki, &isCp);
    jpass = (unsigned char *)(*env)->GetByteArrayElements(env, pass, &isCp);
    jdata_ki = ( unsigned char *) (*env)->GetPrimitiveArrayCritical(env, data_ki, &isCp);
    //jdata_ki = (unsigned char *)malloc(len_data_ki);
    //(*env)->GetByteArrayRegion(env, data_ki, 0, len_data_ki, jdata_ki);

    jlen_data_ki_crypted = len_data_ki+LEN_IMZ_4;
    data_ki_crypted = (*env)->NewByteArray(env, jlen_data_ki_crypted);
    if(data_ki_crypted == NULL)
        return NULL;

    jdata_ki_crypted = (unsigned char *)malloc(jlen_data_ki_crypted);
    if(jdata_ki_crypted == NULL)
        return NULL;

    HeshStruct HeshData;
    HeshData.Data = jpass;
    HeshData.DataLen = (unsigned int)len_pass;
    HeshData.Hesh = (unsigned char *) key;
    HeshData.STATE = 0;
    Hesh341112(HESH_LEN_256, &HeshData);


    if (len_data_ki % 8 != 0) {
        num0 = ((len_data_ki / 8 + 1) * 8) - len_data_ki;
        buffer = (unsigned char *) malloc(len_data_ki + num0);
        memcpy(buffer, jdata_ki, len_data_ki);
        memset(buffer + len_data_ki, 0, num0);
    }
    else {
        buffer = jdata_ki;
    }

#if defined(CRYPT_GOST28147)
    // Расчет имитовставки
    GostStruct gostIMZ;
    gostIMZ.REGIM = MAKE_IMZ;
    gostIMZ.Din = buffer;
    gostIMZ.Dout = imz;
    gostIMZ.LenBytes = len_data_ki+num0;
    gostIMZ.TR_STATE = 0;
    gostIMZ.LenIMZ = LEN_IMZ_4;
    gostIMZ.Key = key;
    gostIMZ.Tz = (unsigned char *)TABLE;
    Gost28147(&gostIMZ);

	// Шифрование
    GostStruct Cript;
	Cript.REGIM	= GAMMIROVANIE_OS_REG;
	Cript.CRYPT	= ENCRYPT;
	Cript.Key	= key;
	Cript.Sp	= (unsigned int *)sp;
	Cript.Din	= jdata_ki;
	Cript.Dout	= jdata_ki_crypted;
	Cript.LenBytes = len_data_ki;
	Cript.TR_STATE = TR_NO;
	Cript.Tz	= (unsigned char *)TABLE;
	Gost28147(&Cript);
#elif defined(CRYPT_MAGMA)
    unsigned char imit_ctx[kImit89ContextLen];
    if(!cypher_magma_imit_init((unsigned char *)key, LEN_IMZ_4, imit_ctx))
        return NULL;
    if(!cypher_imit(imit_ctx, buffer, imz, len_data_ki+num0))
        return NULL;
    free_imit(imit_ctx);

    unsigned char ctx[kCfb89ContextLen];
    if(!cypher_magma_cfb_init((unsigned char *)key, ctx, kBlockLen89, sp, 8))
        return NULL;
    if(!cypher_encr_cfb(ctx, jdata_ki, jdata_ki_crypted, len_data_ki))
        return NULL;
    free_cfb(ctx);
#endif

    if(num0 != 0 && buffer != NULL) {
        free(buffer);
    }

    memcpy(jdata_ki_crypted + len_data_ki, imz, LEN_IMZ_4);

    //(*env)->ReleaseByteArrayElements(env, data_ki, jdata_ki, JNI_ABORT);
    //free(jdata_ki);
    (*env)->ReleaseByteArrayElements(env, pass, jpass, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, data_ki, jdata_ki, JNI_ABORT);
    (*env)->SetByteArrayRegion(env, data_ki_crypted, 0, len_data_ki+LEN_IMZ_4, jdata_ki_crypted);
    free(jdata_ki_crypted);

    return data_ki_crypted;
}

*/


JNIEXPORT void JNICALL Java_org_pniei_portal_vpn_VpnClient_testspeedchain(JNIEnv *env, jobject this, jbyteArray tunnels) {
    unsigned char isCp;
    unsigned char * jtunnels;
    int jlen_tunnels;


    if(tunnels == NULL)
        return;

    jtunnels = (unsigned char *)(*env)->GetByteArrayElements(env, tunnels, &isCp);
    jlen_tunnels = (*env)->GetArrayLength(env, tunnels);

    mmt_save_tunnel(jtunnels, jlen_tunnels);
}

JNIEXPORT jint JNICALL
Java_org_pniei_portal_vpn_VpnClient_crc32(JNIEnv *env, jclass clazz, jbyteArray buff, jint off, jint len) {
    unsigned char isCp;
    unsigned char * jbuff, *temp_buff;
    int len_temp_buff;
    unsigned int crc;

    jbuff = (unsigned char *)(*env)->GetByteArrayElements(env, buff, &isCp);

    if(len%2 > 0) {
        len_temp_buff = len + 1;
        temp_buff = (unsigned char *)malloc(len_temp_buff);
        temp_buff[len] = 0;
    }
    else {
        len_temp_buff = len;
        temp_buff = (unsigned char *)malloc(len_temp_buff);
    }

    memcpy(temp_buff, jbuff+off, len);
    crc = KS_MOD32(((unsigned short *) temp_buff), len_temp_buff/2, 0, 1);
    (*env)->ReleaseByteArrayElements(env, buff, jbuff, JNI_ABORT);

    return (jint) crc;
}

JNIEXPORT jint JNICALL
Java_org_pniei_portal_vpn_VpnClient_crc32sim(JNIEnv *env, jclass clazz, jbyteArray buff, jint len) {
    unsigned char isCp;
    unsigned char * jbuff;
    unsigned int crc;

    jbuff = (unsigned char *)(*env)->GetByteArrayElements(env, buff, &isCp);
    crc = crc32(jbuff, len);
    (*env)->ReleaseByteArrayElements(env, buff, jbuff, JNI_ABORT);
    return crc;
}
