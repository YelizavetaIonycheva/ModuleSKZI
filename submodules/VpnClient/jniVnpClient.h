
#include "vpnClient.h"
#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

JNIEXPORT void JNICALL
Java_org_pniei_portal_vpn_VpnClient_ikev2init(JNIEnv *env, jobject this,
											 jshort netNumber, jint lanPort, jbyteArray lanIPAdr,
											 jshort serverNetNumber, jint wanPort, jbyteArray wanIPAdr,
											 jbyteArray nameKompl, jbyteArray numSerial, jshort numKompl,
											 jshort numOfKeys, jint random, jbyteArray tz, jbyteArray keydsch);

JNIEXPORT jbyteArray JNICALL
Java_org_pniei_portal_vpn_VpnClient_ikev2getikesainit(JNIEnv *env, jobject this,
                                                                jintArray lenData);

JNIEXPORT void JNICALL
Java_org_pniei_portal_vpn_VpnClient_vpnprocessingdata(JNIEnv *env, jobject this,
                                                                jbyteArray dataIn, jint lenDataIn,
                                                                jbyteArray dataOut,
                                                                jintArray lenDataOut,
                                                                jintArray target, jintArray err);

JNIEXPORT jint JNICALL
Java_org_pniei_portal_vpn_VpnClient_getikev2stage(JNIEnv *env, jobject this);

JNIEXPORT jint JNICALL
Java_org_pniei_portal_vpn_VpnClient_getikev2ipaddr(JNIEnv *env, jobject this);

JNIEXPORT jint JNICALL
Java_org_pniei_portal_vpn_VpnClient_getikev2ipmask(JNIEnv *env, jobject this);

JNIEXPORT jint JNICALL
Java_org_pniei_portal_vpn_VpnClient_checktimesa(JNIEnv *env, jobject this);

JNIEXPORT jint JNICALL
Java_org_pniei_portal_vpn_VpnClient_espencapsuldata(JNIEnv *env, jobject this,
											   jbyteArray dataIn, jbyteArray dataOut,
											   jint lenDataIn, jintArray lenDataOut);

JNIEXPORT jint JNICALL
Java_org_pniei_portal_vpn_VpnClient_packetforanothernetwork(JNIEnv *env, jobject this,
                                                                      jbyteArray dataIn,
                                                                      jint lenData,
                                                                      jbyteArray dataOut,
                                                                      jintArray lenProcData);

JNIEXPORT jint JNICALL
Java_org_pniei_portal_vpn_VpnClient_ikev2checkadditionalsa(JNIEnv *env, jobject this,
                                                                     jbyteArray dataOut,
                                                                     jintArray lenProcData);

JNIEXPORT void JNICALL
Java_org_pniei_portal_vpn_VpnClient_ikev2getkeepalive(JNIEnv *env, jobject this,
                                                                jbyteArray dataOut,
                                                                jintArray lenProcData);

JNIEXPORT void JNICALL
Java_org_pniei_portal_vpn_VpnClient_ikev2getdelete(JNIEnv *env, jobject this,
																jbyteArray dataOut,
																jintArray lenProcData);

JNIEXPORT void JNICALL
Java_org_pniei_portal_vpn_VpnClient_ikev2getnetworksettings(JNIEnv *env, jobject this,
                                                                      jbyteArray dataOut,
                                                                      jintArray lenProcData);

JNIEXPORT void JNICALL
Java_org_pniei_portal_vpn_VpnClient_ikev2getikedelete(JNIEnv *env, jobject this,
                                                                jbyteArray dataOut,
                                                                jintArray lenProcData);

JNIEXPORT jboolean JNICALL
Java_org_pniei_portal_vpn_VpnClient_isNAT(JNIEnv *env, jobject this);

JNIEXPORT void JNICALL
Java_org_pniei_portal_vpn_VpnClient_ikev2clear(JNIEnv *env, jobject this);

JNIEXPORT jbyteArray JNICALL
Java_org_pniei_portal_vpn_VpnClient_decryptkomplkeys(JNIEnv *env, jobject this, jbyteArray crypted_data_ki);

JNIEXPORT jbyteArray JNICALL
Java_org_pniei_portal_vpn_VpnClient_cryptdata(JNIEnv *env, jobject this, jbyteArray open_data_ki,
										 jbyteArray key);

JNIEXPORT jbyteArray JNICALL
Java_org_pniei_portal_vpn_VpnClient_decryptdata(JNIEnv *env, jobject this,
                                         jbyteArray crypted_data,
                                         jbyteArray key);
/*
JNIEXPORT jint JNICALL
Java_org_pniei_portal_vpn_VpnClient_crc32(JNIEnv *env, jobject this, jbyteArray buf,
                                                    jint lenBuf);
*/

JNIEXPORT void JNICALL 
Java_org_pniei_portal_vpn_VpnClient_testmagma(JNIEnv *env, jobject this);

JNIEXPORT void JNICALL 
Java_org_pniei_portal_vpn_VpnClient_testupdsch(JNIEnv *env, jobject this);

JNIEXPORT void JNICALL 
Java_org_pniei_portal_vpn_VpnClient_setsknkeys(JNIEnv *env, jobject this, jbyteArray data);

JNIEXPORT jbyte JNICALL
Java_org_pniei_portal_vpn_VpnClient_checkkeywithskn(JNIEnv *env, jobject this,
                                        jbyteArray name,
                                        jbyteArray serial,
										jshort kompl);

JNIEXPORT jbyteArray JNICALL
Java_org_pniei_portal_vpn_VpnClient_setnextkeyaswork(JNIEnv *env, jobject this, jbyteArray keyData, jbyteArray nextKey);

JNIEXPORT jbyteArray JNICALL
Java_org_pniei_portal_vpn_VpnClient_checkkeybyskn(JNIEnv *env, jobject this, jbyteArray keyData);

JNIEXPORT jbyteArray JNICALL
Java_org_pniei_portal_vpn_VpnClient_checkkeybydate(JNIEnv *env, jobject this, jbyteArray data_ki, jbyteArray now_date);

JNIEXPORT jint JNICALL
Java_org_pniei_portal_vpn_VpnClient_getcrcsknkeys(JNIEnv *env, jobject this);

JNIEXPORT jbyteArray JNICALL
Java_org_pniei_portal_vpn_VpnClient_searchanddeletekey(JNIEnv *env, jobject this, jbyteArray key_delete, jbyteArray keys);

JNIEXPORT jbyteArray JNICALL
Java_org_pniei_portal_vpn_VpnClient_searchandeditkey(JNIEnv *env, jobject this, jbyteArray key_edit, jbyteArray keys);

JNIEXPORT jbyteArray JNICALL
Java_org_pniei_portal_vpn_VpnClient_addkey(JNIEnv *env, jobject this, jbyteArray key_add, jbyteArray key_data, jbyteArray keys);

JNIEXPORT jbyteArray JNICALL
Java_org_pniei_portal_vpn_VpnClient_testspeed(JNIEnv *env, jobject this, jbyteArray data_ki, jbyteArray pass);

JNIEXPORT void JNICALL
Java_org_pniei_portal_vpn_VpnClient_testspeedchain(JNIEnv *env, jobject this, jbyteArray tunnels);

JNIEXPORT jint JNICALL
Java_org_pniei_portal_vpn_VpnClient_crc32(JNIEnv *env, jclass clazz, jbyteArray buff, jint off, jint len);

JNIEXPORT jint JNICALL
Java_org_pniei_portal_vpn_VpnClient_crc32sim(JNIEnv *env, jclass clazz, jbyteArray buff, jint len);
#ifdef __cplusplus
}
#endif