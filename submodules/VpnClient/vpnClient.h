#ifndef H_VPNCLIENT
#define H_VPNCLIENT

#include <stdlib.h>
#include <jni.h>

#define IKEv2	1
#define ESP		2

/*
void vpnInit(unsigned short netNumber, unsigned short lanPort,
             unsigned char * lanIPAdr, unsigned short serverNetNumber,
             unsigned short  wanPort, unsigned char * wanIPAdr,
             unsigned char * NameBlock, unsigned char * NumSerial,
             unsigned short numOfKeys, unsigned int random, unsigned char * tz,
             unsigned char * key_dsch);
*/
/* Основная функция обработки входных данных
   Определяет являются ли даные IKE или ESP
   Возвращает данные для отправки

   Вход:
		data	- массив, данные UDP пакета
	    lenData - размер входных данных
		target  - куда отправить результ обработки данных ( 0 - NotTarget - отбросить данные,
		                                                    1 - Server - отправка сообщения на сервер,
														    2 - Client - расшифрованные данные на TUN-интерфейс)


*/

int vpnProcessingData(unsigned char * dataIn, unsigned int lenDataIn, unsigned char ** dataOut, int * lenDataOut, int * target);
/*
int vpnEncapsulData(unsigned char * dataIn, unsigned int lenDataIn, unsigned char ** dataOut, int * lenDataOut, int * protocol);

int vpnPacketForAnotherNetwork(unsigned char * dataIn, unsigned int lenDataIn, unsigned char ** dataOut, int * lenDataOut);

int vpnCheckAdditionalSA(unsigned char ** dataOut, unsigned int * lenDataOut);

void vpnGetIKE_SA_INIT(unsigned char ** dataOut, unsigned int * lenDataOut);
*/
void vpnGetKeepalive(unsigned char ** dataOut, int * lenDataOut);
/*
void vpnGetNetworkSettings(unsigned char ** dataOut, unsigned int * lenDataOut);
*/
void vpnGetIkeDelete(unsigned char ** dataOut, int * lenDataOut );

unsigned char vpnIsNat();
/*
int vpnGetIKEv2Stage();

int vpnGetIKEv2IpAddr();

int vpnGetIKEv2IpMask();
*/

void vpnSetJNI(JNIEnv * env/*, jobject this*/);

void vpnClear(JNIEnv *env);

unsigned int vpnCrc(unsigned char * buf, int len);

#endif