#ifndef _IKEv2_H 
#define _IKEv2_H 

#include "IKEv2_Def.h"
#include "queue.h"
#include <jni.h>
#include <pthread.h>
#include <time.h>


typedef struct key_kompl {
	unsigned char  	name[8];	// Наименование комплекта
	unsigned char  	Nserial[8];	// Номер серии
	unsigned short 	numOfKompl; // Кол-во комплектов
	unsigned short 	NKompl;		// Номер комплекта
	unsigned int  	key[8];		// Ключ шифрования
	unsigned char  	Table[8][16];
	unsigned int  	key_dsh[8];
}KEY_KOMPL;

// Структура Преобразования для SA
typedef struct Transform {
	unsigned char type;
	unsigned short id;
} TRANSFORM;

// Структура Предложения для SA
typedef struct Proposal {
	unsigned int num_transf;
	TRANSFORM * transforms;
} PROPOSAL;

typedef struct trefic_selector {
	unsigned short startPort;
	unsigned short endPort;
	unsigned int startAdd;
	unsigned int endAdd;
} TRAF_SELECT;

// Структура контекста безопасности (SA)
typedef struct IKEv2_struct {
	unsigned char initSPI[8];		//IKE_SA Init SPI
	unsigned char respSPI[8];		//IKE_SA Resp SPI
	unsigned int espInitSPI;		//ESP Init SPI
	unsigned int espRespSPI;		//ESP Resp SPI
	unsigned int outSNESP;			//Значение SeqNumber в следующем отправленном пакете ESP
	unsigned int inSNESP;			//Значение SeqNumber в следующем принятом пакете ESP
	unsigned int outMessageID;		//Значение Message ID в следующем отправленном пакете	
	unsigned int inMessageID;		//Значение Message ID в следующем принятом пакете
	unsigned char stage;		//Этап установления контеста: 
								// 0 - не установлен, 
								// 1 - отправлен IKE_SA_INIT на сервер, 
								// 2 - получен IKE_SA_INIT от сервера,
								// 3 - отправлен IKE_AUTH на сервер
								// 4 - получен IKE_AUTH - установление  контекста завершено
	unsigned char role;         // Роль устройства в этом соединении:
	                            // 0 - Инициатор
	                            // 1 - Ответчик
	unsigned char * nonceI;		//Нонс инициатора
	unsigned char * nonceR;		//Нонс ответчика
	unsigned char haveNAT;
	unsigned char num_prop;
	PROPOSAL * proposals;
	KEY_KOMPL  blockNote;		// блокнот ключевой инф
	unsigned int  Kei[8];
	unsigned int  Ker[8];
	unsigned int  Kai[8];
	unsigned int  Kar[8];
	unsigned int  Kpacket[8];
	int indexKeySA;	// Индекс ключа в массиве ключей для которого установлен контекст безопасности

	// Инфа из блока CP
	unsigned int IP_addr;
	unsigned int IP_mask;

	// Инфа из блока  TSi
	unsigned char numSTi;
	TRAF_SELECT * TSi;
	// Инфа из блока  TSr
	unsigned char numSTr;
	TRAF_SELECT * TSr;

	unsigned short lanPort;
	unsigned char lanIpAdr[4];
	unsigned short wanPort;
	unsigned char wanIpAdr[4];
    unsigned short netNumber;
    unsigned short serverNetNumber;
	unsigned char *SecureIdentifyInf;

} IKEv2_STRUCT_SA;

typedef struct {
	IKEv2_STRUCT_SA * ikev2_sa;
	time_t time_end;
	unsigned char flag_checked;
} IKEv2_SA_PULL;

extern jobject THIS;
extern JNIEnv * ENV;
//extern IKEv2_STRUCT_SA * ikev2_sa;
extern IKEv2_SA_PULL ikev2_sa_pull[];
extern int index_main_ikev2_sa;
extern pthread_mutex_t ikev2_sa_mutex;
extern pthread_mutex_t ikev2_sa_mutex_processing_data;
extern pthread_mutex_t ikev2_sa_mutex_keepalive;
extern pthread_mutex_t ikev2_sa_mutex_encapsul_data;

extern QUEUE * queue_ikev2_sa;
//---------Структуры блоков данных---------------

// Блок данных HDR
typedef struct ikev2_block_hdr {
	unsigned char 	initSPI[8];		//IKE_SA Init SPI
	unsigned char 	respSPI[8];		//IKE_SA Resp SPI
	unsigned char	nextPayload;
	unsigned char	vers;			//старшая и младшая часть версии
	unsigned char	exchangeType; 
	unsigned char	flags;
	unsigned int	messageID;		//Message ID
	unsigned int	length;		//Длина всего сообщения
}ikev2_block_HDR;

// Структура Преобразование
typedef struct ikev2_block_transf {
	unsigned char	LorM;			//last or more
	unsigned char	reserved0;		
	unsigned short	length;
	unsigned char	type;			//старшая и младшая часть версии
	unsigned char	reserved1;
    unsigned short	id;
	//без атрибутов еще
}ikev2_block_TRANSF;

// Структура Предложение
typedef struct ikev2_block_prop {
	unsigned char	LorM;			//last or more
	unsigned char	reserved;		
	unsigned short	length;
	unsigned char	number;			
	unsigned char	id; 
	unsigned char	SPIsize;
	unsigned char	numOfTransf;
	unsigned int	spi;
	ikev2_block_TRANSF * transforms;
	//без атрибутов еще
}ikev2_block_PROP;

// Блок данных SA
typedef struct ikev2_block_sa {
	unsigned char	nextPayload;
	unsigned char	C;
	unsigned short	length;
	ikev2_block_PROP *	proposals;
}ikev2_block_SA;

// Блок данных KE
typedef struct ikev2_block_ke {
	unsigned char	nextPayload;
	unsigned char	C;
	unsigned short	length;
	unsigned short  DH_Group;
	unsigned short	reserved;
	unsigned char *	KE_Data;
}ikev2_block_KE;

// Блок данных N (Nonce)
typedef struct ikev2_block_nonce {
	unsigned char	nextPayload;
	unsigned char	C;
	unsigned short	length;
	unsigned char *	N_Data;
}ikev2_block_NONCE;

typedef struct ikev2_block_notify {
	unsigned char	nextPayload;
	unsigned char	C;
	unsigned short	length;
	unsigned char	protocolID;
	unsigned char	sizeSPI;
	unsigned short	notifyMessageType;
	unsigned char *	spi;
	unsigned char *	Notify_Data;
} ikev2_block_NOTIFY;

typedef struct ikev2_block_vendorid {
	unsigned char	nextPayload;
	unsigned char	C;
	unsigned short	length;
	unsigned char *	id;
} ikev2_block_VendorID;

// Блок данных AUTH
typedef struct ikev2_block_auth {
	unsigned char	nextPayload;
	unsigned char	C;
	unsigned short	length;
	unsigned char	A_Method;
	unsigned char   reserver0;
	unsigned short	reserver1;
	unsigned char *	A_Data;
}ikev2_block_AUTH;

// Блок данных ID
typedef struct ikev2_block_ident {
	unsigned char	nextPayload;
	unsigned char	C;
	unsigned short	length;
	unsigned char	idType;
	unsigned char   reserver0;
	unsigned short	reserver1;
	unsigned char *	ID_Data;
}ikev2_block_IDENT;

//Блок данных SK
typedef struct ikev2_block_sk {
	unsigned char	nextPayload;
	unsigned char	C;
	unsigned short	length;
	unsigned char	VI[8];
	unsigned char	IZV[8];
	unsigned char * encrData;
	unsigned char	IMZ[8];
}ikev2_block_SK;

//Блок данных Delete
typedef struct ikev2_block_delete {
    unsigned char	nextPayload;
    unsigned char	C;
    unsigned short	length;
    unsigned char	protocolID;
    unsigned char	sizeSPI;
    unsigned short  numOfSPIs;
    unsigned char *	SPI;
} ikev2_block_DELETE;

//Блок данных CP
typedef struct ikev2_block_cp {
	unsigned char	nextPayload;
	unsigned char	C;
	unsigned short	length;
	unsigned char	CFG_Type;
	unsigned char   reserver0;
	unsigned short	reserver1;
	unsigned short	A_Type1;
	unsigned short	A_Type1_length;
	unsigned int	value1;
	unsigned short	A_Type2;
	unsigned short	A_Type2_length;
	unsigned int	value2;
}ikev2_block_CP;

// Струтура селектора трафика
typedef struct ikev2_block_traf_select {
	unsigned char	TS_Type;
	unsigned char	IP_ID;
	unsigned short	length;
	unsigned short	start_port;
	unsigned short	end_port;
	unsigned int	start_address;
	unsigned int	end_address;
}ikev2_block_TRAF_SELECT;

// Блок данных TS
typedef struct ikev2_block_traf_selects {
	unsigned char	nextPayload;
	unsigned char	C;
	unsigned short	length;
	unsigned char	numOfTSs;
	unsigned char   reserver0;
	unsigned short	reserver1;
	ikev2_block_TRAF_SELECT	*	ID_Data;
}ikev2_block_TRAF_SELECTS;



int get_ikev2_stage(void);

int get_ikev2_ip_addr(void);
int get_ikev2_ip_mask(void);


// Функции

//Функция создания контекста
int ikev2_sa_init(unsigned short net_number, unsigned short lan_port,
							unsigned char *lan_ip_addr, unsigned short server_net_number,
							unsigned short wan_port, unsigned char *wan_ip_addr,
							unsigned char *name_kompl, unsigned char *serial, unsigned short num_kompl,
							unsigned short num_ofKeys, unsigned int random, unsigned char *tz,
							unsigned char * key_dsch);

void ikev2_get_ike_sa_init(unsigned char ** data_out, int * len_data_out, IKEv2_STRUCT_SA * ikev2_sa);
void ikev2_get_ike_auth(unsigned char ** data_out, int * len_data_out, IKEv2_STRUCT_SA * ikev2_sa);
void ikev2_get_keepalive(unsigned char ** data_out, int * len_data_out);
void ikev2_get_ike_delete(unsigned char ** data_out, int * len_data_out);
void ikev2_get_network_settings(unsigned char ** dataOut, int * lenDataOut);

unsigned int reverse32(unsigned int a);
unsigned short reverse16(unsigned short a);

//Функция проверки контекста к отправке IKE_AUTH
unsigned char check_ikesa_stage(IKEv2_STRUCT_SA * sa);


// Функции обработки данных протокола IKEv2

int ikev2_processing_data(unsigned char * data_in, int len_data_in, unsigned char ** data_out, int * len_data_out);

// Функция заполения структуры ikev2_block_HDR из массива данных
void createBlockHDRfromBuf(unsigned char * data, ikev2_block_HDR * block_HDR);
// Функция заполения структуры ikev2_block_SA из массива данных
// Должна возвращать код ошибки
int createBlockSAfromBuf(unsigned char * data, int lenData, ikev2_block_SA * block_SA);

// Функция заполения массива структур ikev2_block_PROP
// Должна возвращать код ошибки
int createBlocksProposalFromBuf(unsigned char * data, int lenData, ikev2_block_PROP ** proposals);

// Функция заполения массива структур ikev2_block_TRANSF
// Должна возвращать код ошибки
int createBlocksTransformsFromBuf(unsigned char * data, int lenData, int numTransforms, ikev2_block_TRANSF ** transforms);


// Функция заполения структуры ikev2_block_KE из массива данных
// Должна возвращать код ошибки
int createBlockKEfromBuf(unsigned char * data, int lenData, ikev2_block_KE * block_KE);


// Функция заполения структуры ikev2_block_NONCE из массива данных
// Должна возвращать код ошибки
int createBlockNoncefromBuf(unsigned char * data, int lenData, ikev2_block_NONCE * block_Nonce);


int createBlockVendorIDfromBuf(unsigned char * data, int lenData, ikev2_block_VendorID * block_VendorID);


int createBlockNotifyfromBuf(unsigned char * data, int lenData, ikev2_block_NOTIFY * block_Notify);


int createBlockSKfromBuf(unsigned char * data, int lenData, ikev2_block_SK * block_SK);


int createBlockIDfromBuf(unsigned char * data, int lenData, ikev2_block_IDENT * block_IDENT);


int createBlockAUTHfromBuf(unsigned char * data, int lenData, ikev2_block_AUTH * block_AUTH);


int createBlockCPfromBuf(unsigned char * data, int lenData, ikev2_block_CP * block_CP);


int createBlockTRAFSELECTSfromBuf(unsigned char * data, int lenData, ikev2_block_TRAF_SELECTS * block_TRAF_SELECTS);


int createBlockDeletefromBuf(unsigned char * data, int lenData, ikev2_block_DELETE * block_DELETE);


int check_tsi_tsr( unsigned char protocol, unsigned char * inBuf, IKEv2_STRUCT_SA * ikev2_sa);


int ikev2_decriptSK(ikev2_block_SK * block_SK, IKEv2_STRUCT_SA * ikev2_sa);


int ikev2_processing_Notify(unsigned char * data, int lenData);


int ikev2_check_ike_sa_auth(unsigned char *dataIn, int lenDataIn, IKEv2_STRUCT_SA * ikev2_sa);

int ikev2_check_time_sa();

void ikev2_clear(IKEv2_STRUCT_SA * ikev2_sa);

void ikev2_close();
#endif