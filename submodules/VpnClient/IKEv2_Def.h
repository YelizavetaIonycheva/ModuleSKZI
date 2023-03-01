#ifndef _IKEv2_DEF_H 
#define _IKEv2_DEF_H 

// Алгоритм шифрования

//#define CRYPT_GOST28147
//#define CRYPT_MAGMA


// Exchange Type
#define IKE_SA_INIT		34
#define IKE_AUTH		35
#define INFORMATIONAL	37
#define KEEPALIVE   	240

//Типы блоков данных (Next Payload)
#define		ikev2_np_not		0
#define		ikev2_np_sa			33
#define		ikev2_np_ke			34
#define		ikev2_np_idi		35
#define		ikev2_np_idr		36
#define		ikev2_np_cert		37
#define		ikev2_np_certreq	38
#define		ikev2_np_auth		39
#define		ikev2_np_nonce		40
#define		ikev2_np_notify		41
#define		ikev2_np_delete		42
#define		ikev2_np_vendor		43
#define		ikev2_np_TSi		44
#define		ikev2_np_TSr		45
#define		ikev2_np_SK			46
#define		ikev2_np_conf		47
#define		ikev2_np_eap		48

//Размеры заголовков блоков даных
#define		ikev2_SIZE_HDR			28
#define		ikev2_SIZE_TRANSFORM_H	8
#define		ikev2_SIZE_PROPOSAL_H	8  // Без SPI
#define		ikev2_SIZE_SA_H			28 // заголовок + синхро + изв + имитовставка
#define		ikev2_SIZE_NONCE_H		12
#define		ikev2_SIZE_KE_H			8  // только заголовок
#define		ikev2_SIZE_ID_H			28
#define		ikev2_SIZE_AUTH_H		24	
#define		ikev2_SIZE_SK_H			28 // заголовок + синхро + изв + имитовставка
#define		ikev2_SIZE_ESP_H		32 // SPI + SN + SP + IMZ + CRC
#define		ikev2_SIZE_NOTIFY_H		8
#define     ikev2_SIZE_START_ZERO   4
#define     ikev2_SIZE_VID_H		14


#define     ikev2_size_Key_data     20

#define		ikev2_SIZE_ESP_H_TO_IMZ 16 // Размер данных (заголовка ESP) на которые считается имитозащита

#define     ikev2_SIZE_ESP_SN_WINDOW 16 // Размер окна порядкового номера в пакете ESP
#define     ikev2_SIZE_IKE_SN_WINDOW 16 // Размер окна порядкового номера в пакете IKE
                                        // Максимальная разница между номером пакета который ожидался и номером пакета который пришел

//Сообщения уведомления - Типы ошибок
#define		UNSUPPORTED_CRITICAL_PAYLOAD	1
#define		INVALID_IKE_SPI					4
#define		INVALID_MAJOR_VERSION			5
#define		INVALID_SYNTAX					7
#define		INVALID_MESSAGE_ID				9
#define		INVALID_SPI						11
#define		NO_PROPOSAL_CHOSEN				14
#define		INVALID_KEY_PAYLOAD				17
#define		AUTHENTICATION_FAILED			24
#define		SINGLE_PAIR_REQUIRED			34
#define		NO_ADDITIONAL_SAS				35
#define		INTERNAL_ADDRESS_FAILURE		36
#define		FAILED_CP_REQUIRED				37
#define		TS_UNACCEPTABLE					38
#define		INVALID_SELECTORS				39


//Сообщения уведомления - Типы состояний
#define		INITIAL_CONTACT					16384
#define		SET_WINDOW_SIZE					16385
#define		ADDITIONAL_TS_POSSIBLE			16386
#define		IPCOMP_SUPPORTED				16387
#define		NAT_DETECTION_SOURCE_IP			16388
#define		NAT_DETECTION_DESTINATION_IP	16389
#define		COOKIE							16390
#define		USE_TRANSPORT_MODE				16391
#define		HTTP_CERT_LOOKUP_SUPPORTED		16392
#define		REKEY_SA						16393
#define		ESP_TFC_PADDING_NOT_SUPPORTED	16394
#define		NON_FIRST_FRAGMENTS_ALSO		16395
#define		GET_NETWORK_SETTINGS    		40992
#define		SET_NETWORK_SETTINGS    		40993
	
// Номера протоколов 
#define		IPV4							4

//Этапы установления контеста:
// 0 - не установлен,
// 1 - отправлен IKE_SA_INIT на сервер,
// 2 - получен IKE_SA_INIT от сервера,
// 3 - отправлен IKE_AUTH на сервер
// 4 - получен IKE_AUTH - установление  контекста завершено

#define IKE_STAGE_0     0
#define IKE_STAGE_1     1
#define IKE_STAGE_2     2
#define IKE_STAGE_3     3
#define IKE_STAGE_4     4

#define IKE_INITIATOR   1
#define IKE_RESPONDER   0

//#define NULL 0

#define TIME_T 300 // Время работы контекста в секундах
#define TIME_t 60 // Время до окончания текущего контекста, когда нужно создавать новый

/**   Коды результатов выполнения   **/

#define IKE_OK              0x0
#define IKE_ERR             0x666
#define IKE_SEND            0x1
#define IKE_KEPPALIVE_RECEIVED       0x2
#define IKE_KEPPALIVE_ADDITIONAL_RECEIVED 0x3
#define IKE_CONTEXT_DEL     0x4
#define IKE_KEPPALIVE_SEND  0x5
#define IKE_NETWORK_SETTING 0x6
#define IKE_ADDITIONAL_DELETE 0x7
#define IKE_OLD_CONTEXT_DEL   0x8

#define IKE_ERR_STAGE       			0x0010
#define IKE_ERR_MID         			0x0011
#define IKE_ERR_MID_OVER    			0x0012
#define IKE_ERR_ETYPE_UNSUP 			0x0013
#define IKE_ERR_LEN         			0x0014
#define IKE_ERR_INDEX_KEY_SA 			0x0015
#define IKE_ERR_CRIPT_KEY   			0x0016
#define IKE_ERR_PROTOC_UNSUP 			0x0017
#define IKE_ERR_IMZ_HDR     			0x0018
#define IKE_ERR_IMZ_ESP_HDR     		0x0019
#define IKE_ERR_SN_OVER     			0x001A
#define IKE_ERR_SUPPORT_ONLY_IPV4     	0x001B
#define IKE_ERR_IMZ_SK      			0x001C
#define IKE_ERR_AUTHDATA    			0x001D
#define IKE_ERR_IMZ_INFORM  			0x001E
#define IKE_ERR_NOTIFY_MESSAGE_TYPE  	0x001F
#define IKE_ERR_TUNNELS_ALREADY_SAVED 	0x0020
#define IKE_ERR_MEMORY      			0x0021
#define IKE_ERR_TUNNELS_BUF_EMPTY      	0x0022
#define IKE_ERR_SA_ADDIT_FULL          	0x0023
#define IKE_ERR_VENDOR_ID        		0x0024
#define IKE_ERR_CRYPT_ALG_NOT_FOUND 	0x0025
#define IKE_ERR_MAGMA_IMIT_INIT      	0x0026
#define IKE_ERR_MAGMA_IMIT      	    0x0027
#define IKE_ERR_MAGMA_CFB_INIT      	0x0028
#define IKE_ERR_MAGMA_DECR     	        0x0029
#define IKE_ERR_MAGMA_CRPT     	        0x002A
#define IKE_ERR_IMZ_ESP_DATA     		0x002B

#define IKE_ERR_HDR_SPI     0x0100
#define IKE_ERR_HDR_NP      0x0101
#define IKE_ERR_HDR_VER     0x0102
#define IKE_ERR_HDR_FLAG    0x0103

#define IKE_ERR_SA_NP       0x0200

#define IKE_ERR_KE_NP       0x0300
#define IKE_ERR_KE_DHG      0x0301

#define IKE_ERR_NOTIFY_MT   0x0400

#define IKE_ERR_TS_NULL     0x0500

#define IKE_ERR_TSI_OVER     0x0600
#define IKE_ERR_TSR_OVER     0x0601

#define IKE_ERR_SK_NP       0x0700

#define IKE_ERR_ID_NP       0x0800
#define IKE_ERR_ID_IDTYPE   0x0801

#define IKE_ERR_AUTH_NP     0x0900
#define IKE_ERR_AUTH_AMET   0x0901

#define IKE_ERR_DELETE_NP   0x0A00
#define IKE_ERR_DELETE_PROTID   0x0A01

#endif