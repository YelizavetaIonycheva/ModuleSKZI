#include "vpnClient.h"
#include "IKEv2.h"
#include "ESP.h"
#include "MMT.h"
#include "crc32.h"
#include <string.h>

/*
 * out result
 * 0 - данные обработаны, отправить куда указывает target
 * 2 - получен ответ на keppalive
 * 3 - получен запрос на удаление соединения
 * 1 - установлено соединение с СКЗИ
 * далее - код ошибки
 */


int vpnProcessingData(unsigned char * dataIn, unsigned int lenDataIn, unsigned char ** dataOut, int * lenDataOut, int * target) {
	char protocol;
	unsigned int result;
	// Определение Протокола IKEv2 или ESP

	protocol = *(unsigned int *)dataIn == 0 ? IKEv2 : ESP;

	switch(protocol) {
	case IKEv2: {
		pthread_mutex_lock(&ikev2_sa_mutex_processing_data);
		result = ikev2_processing_data(dataIn+4, lenDataIn-4, dataOut, lenDataOut);
		pthread_mutex_unlock(&ikev2_sa_mutex_processing_data);

		switch(result) {
			case IKE_SEND:
			case IKE_KEPPALIVE_SEND : {
				result = IKE_OK;
                *target = 1;    // к Серверу
                break;
            }
			case IKE_CONTEXT_DEL:
			case IKE_KEPPALIVE_RECEIVED:
			case IKE_KEPPALIVE_ADDITIONAL_RECEIVED:{
            	break;
            }
			default: {
                //result = IKE_ERR;
			}
		}
		break;
	}
	case ESP: {
		pthread_mutex_lock(&ikev2_sa_mutex_processing_data);
		result = esp_processing_data(dataIn, lenDataIn, dataOut, lenDataOut);
		pthread_mutex_unlock(&ikev2_sa_mutex_processing_data);

        switch(result) {
            case IKE_SEND:
            case IKE_CONTEXT_DEL: {
                result = IKE_OK;
                *target = 2;    // к Серверу
                break;
            }
            case IKE_OK :{
                *target = 0; // Отбросить
            }
            default: {
                //result = IKE_ERR;
                *target = 0; // Отбросить
            }
        }
        break;
	}
	default: {
		*target = 0;
		result = IKE_ERR_PROTOC_UNSUP;
	}
	}
	return result;
}
/*
int vpnEncapsulData(unsigned char * dataIn, unsigned int lenDataIn, unsigned char ** dataOut, unsigned int * lenDataOut, int * protocol) {
	return esp_encapsul_data(dataIn, lenDataIn, dataOut, lenDataOut, protocol);
}

int vpnPacketForAnotherNetwork(unsigned char * dataIn, unsigned int lenDataIn, unsigned char ** dataOut, unsigned int * lenDataOut) {
	return proc_pack_for_another_network(dataIn, lenDataIn, dataOut, lenDataOut);
}

int vpnCheckAdditionalSA(unsigned char ** dataOut, unsigned int * lenDataOut) {
	return check_ikev2_sa_a(dataOut, lenDataOut);
}
*/
void vpnGetKeepalive(unsigned char ** dataOut, int * lenDataOut) {
	pthread_mutex_lock(&ikev2_sa_mutex_keepalive);
    ikev2_get_keepalive(dataOut, lenDataOut);
	pthread_mutex_unlock(&ikev2_sa_mutex_keepalive);
}
/*
void vpnGetNetworkSettings(unsigned char ** dataOut, unsigned int * lenDataOut) {
    ikev2_get_network_settings(dataOut, lenDataOut);
}
*/
void vpnGetIkeDelete(unsigned char ** dataOut, int * lenDataOut) {
    ikev2_get_ike_delete(dataOut, lenDataOut);
}

unsigned char vpnIsNat() {
    return ikev2_sa_pull[index_main_ikev2_sa].ikev2_sa->haveNAT;
}
/*
int vpnGetIKEv2Stage() {
	return get_ikev2_stage();
}

int vpnGetIKEv2IpAddr() {
	return get_ikev2_ip_addr();
}

int vpnGetIKEv2IpMask() {
	return get_ikev2_ip_mask();
}
*/
void vpnSetJNI(JNIEnv * env/*, jobject this*/) {
	ENV = env;
	//THIS = this;
}

void vpnClear(JNIEnv *env) {
	ENV = NULL;
	THIS = NULL;
    ikev2_close();
}

unsigned int vpnCrc(unsigned char * buf, int len) {
	return crc32(buf, len);
}
