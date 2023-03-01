#include <stdlib.h>
#include <string.h>

#include "updsch_manager.h"
#include "IKEv2.h"
#include "check_IKEv2.h"
#include "crc32.h"
#include "F.h"
#include "MMT.h"
#include "nonce.h"

#if defined(CRYPT_GOST28147)
	#include "Gost28147.h"
#elif defined(CRYPT_MAGMA)
	#include "cypher.h"
#endif

JNIEnv * ENV;
jobject THIS;

IKEv2_SA_PULL ikev2_sa_pull[] = {{NULL, 0, 0}, {NULL, 0, 0}};
int index_main_ikev2_sa = -1;
int index_new_ikev2_sa = -1;
pthread_mutex_t ikev2_sa_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t ikev2_sa_mutex_processing_data = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t ikev2_sa_mutex_keepalive = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t ikev2_sa_mutex_encapsul_data = PTHREAD_MUTEX_INITIALIZER;

int get_ikev2_stage(void) {
    IKEv2_STRUCT_SA * ikev2_sa = ikev2_sa_pull[index_new_ikev2_sa].ikev2_sa;
    if (ikev2_sa != NULL)
	    return ikev2_sa->stage;
    else
        return 0;
}

int get_ikev2_ip_addr(void) {
    IKEv2_STRUCT_SA * ikev2_sa = ikev2_sa_pull[index_main_ikev2_sa].ikev2_sa;
    if (ikev2_sa != NULL)
        return ikev2_sa->IP_addr;
    else
        return 0;
}
int get_ikev2_ip_mask(void) {
    IKEv2_STRUCT_SA * ikev2_sa = ikev2_sa_pull[index_main_ikev2_sa].ikev2_sa;
    if (ikev2_sa != NULL)
        return ikev2_sa->IP_mask;
    else
        return 0;
}

/**
 * Функция инициаизации IKE соединения
 * @param net_number
 * @param lan_port
 * @param lan_ip_addr
 * @param server_net_number
 * @param wan_port
 * @param wan_ip_addr
 * @param name_kompl
 * @param serial
 * @param num_kompl
 * @param num_of_keys
 * @param random
 * @param tz
 * @param key_dsch
 * @return
 */
int ikev2_sa_init(unsigned short net_number, unsigned short lan_port,
							unsigned char *lan_ip_addr, unsigned short server_net_number,
							unsigned short wan_port, unsigned char *wan_ip_addr,
							unsigned char *name_kompl, unsigned char *serial, unsigned short num_kompl,
							unsigned short num_of_keys, unsigned int random, unsigned char *tz,
                            unsigned char * key_dsch) {
	TRANSFORM *transf;
	PROPOSAL *proposal;
    IKEv2_STRUCT_SA * ikev2_sa;
	transf = (TRANSFORM *) malloc(sizeof(TRANSFORM) * 2);
	transf[0].type = 1;
	transf[0].id = 1024;
	transf[1].type = 3;
	transf[1].id = 1024;
	proposal = (PROPOSAL *) malloc(sizeof(PROPOSAL));
	proposal->num_transf = 2;
	proposal->transforms = transf;

	ikev2_sa = (IKEv2_STRUCT_SA *) malloc(sizeof(IKEv2_STRUCT_SA));

	if (ikev2_sa == NULL)
		return IKE_ERR;

	memset(ikev2_sa, 0, sizeof(IKEv2_STRUCT_SA));

	ikev2_sa->stage = IKE_STAGE_0;
	// Составление SPI
	*(unsigned short *) (ikev2_sa->initSPI) = (unsigned short) (rand() % 0xFFFF);
	*((unsigned short *) (ikev2_sa->initSPI) + 1) = net_number;
	*((unsigned short *) (ikev2_sa->initSPI) + 2) = server_net_number;
	*((unsigned short *) (ikev2_sa->initSPI) + 3) = (unsigned short) (rand() % 0xFFFF);

	ikev2_sa->nonceI = (unsigned char *) malloc(8);
	ikev2_sa->nonceR = NULL;

	ikev2_sa->num_prop = 1;
	ikev2_sa->proposals = proposal;

	KEY_KOMPL key_kompl;
	key_kompl.numOfKompl = num_of_keys;
	key_kompl.NKompl = num_kompl;
	if (key_dsch != NULL)
		memcpy((unsigned char *) key_kompl.key_dsh, key_dsch, 32);
	memcpy(key_kompl.name, name_kompl, 8);
	memcpy(key_kompl.Nserial, serial, 8);
	memset((unsigned char *) (key_kompl.key), 0, 32);

	if (tz != NULL) {
		int index = 0;
		for (int j = 0; j < 16; j++) {
			for (int i = 0; i < 8; i += 2) {
				key_kompl.Table[i][j] = tz[index] & 0x0F;
				key_kompl.Table[i + 1][j] = (tz[index] >> 4) & 0x0F;
				index++;
			}
		}
	}

	srand(random);
	nonce_init();

	ikev2_sa->blockNote = key_kompl;
	ikev2_sa->lanPort = lan_port;
	memcpy(ikev2_sa->lanIpAdr, lan_ip_addr, 4);
	ikev2_sa->wanPort = wan_port;
	memcpy(ikev2_sa->wanIpAdr, wan_ip_addr, 4);
	ikev2_sa->netNumber = net_number;
	ikev2_sa->serverNetNumber = server_net_number;
	ikev2_sa->indexKeySA = -1;
	ikev2_sa->role = IKE_INITIATOR;
    ikev2_sa->SecureIdentifyInf = NULL;
	//delete_all_ikev2_sa_a();
    //delete_all_wait_packets();
    //delete_all_tunnels();

	//mmt_save_tunnel(settings, 140);  // DEBUG
#if defined(CRYPT_GOST28147)
	unsigned char i;
	unsigned short n;
	T_EXP[0]=1;
	for(i=1; i>0; i++)
	{
		n=T_EXP[i-1]<<1;
		T_EXP[i]=n^((n>>8)*0x87);
		T_LOG[(n^((n>>8)*0x87))&0xff]=i;
	}
	T_LOG[1]=0;
#endif

	if (index_main_ikev2_sa == -1) {
		index_main_ikev2_sa = 0;
		index_new_ikev2_sa = 0;
		ikev2_sa_pull[index_main_ikev2_sa].ikev2_sa = ikev2_sa;
		ikev2_sa_pull[index_main_ikev2_sa].time_end = time(0) + TIME_T;
		ikev2_sa_pull[index_main_ikev2_sa].flag_checked = 0;
	} else {
		int index = !index_main_ikev2_sa;
		index_new_ikev2_sa = index;
		if (ikev2_sa_pull[index].ikev2_sa != NULL) {
			ikev2_clear(ikev2_sa_pull[index].ikev2_sa);
		}
		ikev2_sa_pull[index].ikev2_sa = ikev2_sa;
		ikev2_sa_pull[index].time_end = time(0) + TIME_T;
		ikev2_sa_pull[index].flag_checked = 0;
	}

	return IKE_OK;
}


 /**
  * Функция генерации сообщения IKE_SA_INIT
  * @param data_out
  * @param len_data_out
  * @param sa
  */
void ikev2_get_ike_sa_init(unsigned char ** data_out, int * len_data_out, IKEv2_STRUCT_SA * ikev2_sa) {
    unsigned char * buffer;

	//Если контекст еще не создавался
	if(ikev2_sa == NULL) {
		*len_data_out = 0;
		*data_out = NULL;
		return;
	}

	memset(ikev2_sa->respSPI, 0, 8);
	ikev2_sa->espInitSPI = 0;
	ikev2_sa->espRespSPI = 0;
	ikev2_sa->outMessageID = 0;
	ikev2_sa->inMessageID = 0;

	//Генерация нонса

	nonce_get((unsigned int *)ikev2_sa->nonceI);

	ikev2_sa->stage = IKE_STAGE_1;

	//Подсчет длины всего сообщения IKE_SA_INIT
	*len_data_out = ikev2_SIZE_HDR +
			   ikev2_SIZE_SA_H +
			   ikev2_SIZE_KE_H +
			   ikev2_size_Key_data +
			   ikev2_SIZE_NONCE_H +
			   24 + // + 2 * 12 (notify)
			   ikev2_SIZE_VID_H;

	buffer = (unsigned char *)malloc(*len_data_out + ikev2_SIZE_START_ZERO);
	memset(buffer, 0, ikev2_SIZE_START_ZERO);
    buffer += ikev2_SIZE_START_ZERO;
	//HDR
	memcpy(buffer, ikev2_sa->initSPI, 8);
	memset(buffer+8, 0, 8);
	*(unsigned char *)(buffer + 16)		= ikev2_np_sa;				// Next Payload
	*(unsigned char *)(buffer + 17)		= 0x20;						// Ver
	*(unsigned char *)(buffer + 18)		= IKE_SA_INIT;				// Exchange Type
	*(unsigned char *)(buffer + 19)		= 0x08;						// Flags
	*(unsigned int *)(buffer + 20)		= 0;						// Message ID
	*(unsigned int *)(buffer + 24)		= reverse32(*len_data_out);

	//SAi
	*(unsigned char *)(buffer + 28)		= ikev2_np_ke;										// Next Payload
	*(unsigned char *)(buffer + 29)		= 0;
	*(unsigned short *)(buffer + 30)	= reverse16(ikev2_SIZE_SA_H);// reverse16((ikev2_SIZE_TRANSFORM_H * ikev2_sa->proposals->num_transf) * ikev2_sa->num_prop + ikev2_SIZE_PROPOSAL_H + ikev2_SIZE_SA_H);

	//Proposals
	*(unsigned char *)(buffer + 32)		= 0;												// last
	*(unsigned char *)(buffer + 33)		= 0;												//RESERVED
	*(unsigned short *)(buffer + 34)	= reverse16((ikev2_SIZE_TRANSFORM_H * ikev2_sa->proposals->num_transf) * ikev2_sa->num_prop + ikev2_SIZE_PROPOSAL_H);  //len
	*(unsigned char *)(buffer + 36)		= 1;												//Переписать формирование массива !!!
	*(unsigned char *)(buffer + 37)		= 1;												//Protocol ID
	*(unsigned char *)(buffer + 38)		= 0;
	*(unsigned char *)(buffer + 39)		= ikev2_sa->proposals->num_transf;

	//Transforms
	*(unsigned char *)(buffer + 40)		= 3;												//more
	*(unsigned char *)(buffer + 41)		= 0;												//RESERVED
	*(unsigned short *)(buffer + 42)	= reverse16(ikev2_SIZE_TRANSFORM_H);				//len
	*(unsigned char *)(buffer + 44)		= ikev2_sa->proposals->transforms[0].type;			//Transform Type
	*(unsigned char *)(buffer + 45)		= 0;												//RESERVED
	*(unsigned short *)(buffer + 46)	= reverse16(ikev2_sa->proposals->transforms[0].id);	//Transform ID

	*(unsigned char *)(buffer + 48)		= 0;												//last
	*(unsigned char *)(buffer + 49)		= 0;												//RESERVED
	*(unsigned short *)(buffer + 50)	= reverse16(ikev2_SIZE_TRANSFORM_H);				//len
	*(unsigned char *)(buffer + 52)		= ikev2_sa->proposals->transforms[1].type;			//Transform Type
	*(unsigned char *)(buffer + 53)		= 0;												//RESERVED
	*(unsigned short *)(buffer + 54)	= reverse16(ikev2_sa->proposals->transforms[1].id); //Transform ID

	//KEi
	*(unsigned char *)(buffer + 56)		= ikev2_np_nonce;									//Next Payload;
	*(unsigned char *)(buffer + 57)		= 0;												//RESERVED
	*(unsigned short *)(buffer + 58)	= reverse16(ikev2_SIZE_KE_H + ikev2_size_Key_data);	//len
	*(unsigned short *)(buffer + 60)	= reverse16(1024);									//DH Group
	*(unsigned short *)(buffer + 62)	= 0;												//RESERVED
	memcpy((buffer + 64), ikev2_sa->blockNote.name, 8);
	memcpy((buffer + 72), ikev2_sa->blockNote.Nserial, 8);
	*(unsigned short *)(buffer + 80) = ikev2_sa->blockNote.NKompl;
	*(unsigned short *)(buffer + 82) = ikev2_sa->blockNote.numOfKompl;

	int sdvig = 64 + ikev2_size_Key_data;

	//Ni
	*(unsigned char *)(buffer + sdvig)			= ikev2_np_notify;				// Next Payload;
	*(unsigned char *)(buffer + sdvig + 1)		= 0;							//RESERVED
	*(unsigned short *)(buffer + sdvig + 2)		= reverse16(ikev2_SIZE_NONCE_H);//len

	memcpy(buffer + sdvig + 4, ikev2_sa->nonceI, 8);

	//N1
	*(unsigned char *)(buffer + sdvig + 12)		= ikev2_np_notify;
	*(unsigned char *)(buffer + sdvig + 13)		= 0;
	*(unsigned short *)(buffer + sdvig + 14)	= reverse16(12);		//len
	*(unsigned char *)(buffer + sdvig + 16)		= 1;
	*(unsigned char *)(buffer + sdvig + 17)		= 0;
	*(unsigned short *)(buffer + sdvig + 18)	= reverse16(NAT_DETECTION_SOURCE_IP);
    unsigned char * data = (unsigned char *) malloc(24);
    memcpy(data, ikev2_sa->initSPI, 8);
    memcpy(data + 8, ikev2_sa->respSPI, 8);
    memcpy(data + 16, (unsigned char *) &ikev2_sa->lanIpAdr, 4);
    memcpy(data + 20, (unsigned char *) &ikev2_sa->lanPort , 2);
    data[22] = 0;
    data[23] = 0;

    unsigned int crc = crc32(data, 24);
    *(unsigned int *)(buffer + sdvig + 20)      = reverse32(crc);

	//N2
	*(unsigned char *)(buffer + sdvig + 24)		= ikev2_np_vendor;
	*(unsigned char *)(buffer + sdvig + 25)		= 0;
	*(unsigned short *)(buffer + sdvig + 26)	= reverse16(12);		//len
	*(unsigned char *)(buffer + sdvig + 28)		= 1;
	*(unsigned char *)(buffer + sdvig + 29)		= 0;
	*(unsigned short *)(buffer + sdvig + 30)	= reverse16(NAT_DETECTION_DESTINATION_IP);
    memcpy(data + 16, (unsigned char *) &ikev2_sa->wanIpAdr, 4);
    memcpy(data + 20, (unsigned char *) &ikev2_sa->wanPort , 2);
    crc = crc32(data, 24);
    *(unsigned int *)(buffer + sdvig + 32)      = reverse32(crc);

	// Vendor ID
	*(unsigned char *)(buffer + sdvig + 36)		= ikev2_np_not;
	*(unsigned char *)(buffer + sdvig + 37)		= 0;
	*(unsigned short *)(buffer + sdvig + 38)	= reverse16(ikev2_SIZE_VID_H);		//len
	*(unsigned int *)(buffer + sdvig + 40)		= 0x462F8A47;
	*(unsigned int *)(buffer + sdvig + 44)		= 0xC6F3510E;
	*(unsigned short *)(buffer + sdvig + 48)	= 0x73D2;

	free(data);
	buffer -= ikev2_SIZE_START_ZERO;
	*data_out = buffer;
    *len_data_out += ikev2_SIZE_START_ZERO;
}

 /**
  * Функция генерации сообщения IKE_SA_AUTH
  * @param data_out
  * @param len_data_out
  * @param sa
  */
void ikev2_get_ike_auth(unsigned char ** data_out, int * len_data_out, IKEv2_STRUCT_SA * ikev2_sa) {
    unsigned int sizeBlockCripto, lenCriptoData;
    unsigned int lenPadLength;
	unsigned char lenPad;
	unsigned char izv[8];
	unsigned int A[4];
	unsigned char temp[32];
    unsigned char * buffer = NULL;

	//Если контекст еще не создавался
	if(ikev2_sa == NULL && ikev2_sa->stage != IKE_STAGE_2) {
		*len_data_out = 0;
		*data_out = NULL;
		return;
	}

	//Подсчет длины всего сообщения IKE_AUTH
	lenCriptoData = ikev2_SIZE_ID_H +
                    ikev2_SIZE_AUTH_H +
                    (ikev2_SIZE_TRANSFORM_H * ikev2_sa->proposals->num_transf) * ikev2_sa->num_prop +
                    ikev2_SIZE_PROPOSAL_H + 8 + 48;

	sizeBlockCripto = 8;
	lenPadLength = 1;
	lenPad = (sizeBlockCripto -  (lenCriptoData + lenPadLength) % sizeBlockCripto);

	*len_data_out = lenPad +
			   lenCriptoData + 
			   ikev2_SIZE_SK_H +
			   ikev2_SIZE_HDR +
			   lenPadLength;

	buffer = (unsigned char *)malloc(*len_data_out+ikev2_SIZE_START_ZERO);
	memset(buffer, 0, ikev2_SIZE_START_ZERO);
    buffer += ikev2_SIZE_START_ZERO;
	//HDR
	memcpy(buffer, ikev2_sa->initSPI, 8);							// Init SPi
	memcpy(buffer+8, ikev2_sa->respSPI, 8);							// Resp SPI

	*(unsigned char *)(buffer + 16)		= ikev2_np_SK;				// Next Payload
	*(unsigned char *)(buffer + 17)		= 0x20;						// Ver
	*(unsigned char *)(buffer + 18)		= IKE_AUTH;					// Exchange Type
	*(unsigned char *)(buffer + 19)		= 0x08;						// Flags
	ikev2_sa->outMessageID = 1;
	*(unsigned int *)(buffer + 20)		= reverse32(ikev2_sa->outMessageID);// Message ID
	*(unsigned int *)(buffer + 24)		= reverse32(*len_data_out);

	//SK
	*(unsigned char *)(buffer + 28)		= ikev2_np_idi;				// Next Payload
	*(unsigned char *)(buffer + 29)		= 0;
	*(unsigned short *)(buffer + 30)		= reverse16(ikev2_SIZE_SK_H + lenCriptoData + lenPad + lenPadLength);

	//*(unsigned int *)(buffer + 32)		= random();				//Initialization Vector
    //*(unsigned int *)(buffer + 36)		= random();				//Initialization Vector
	memcpy(buffer + 32, get_random(ikev2_sa->SecureIdentifyInf), 8);

#if defined(CRYPT_GOST28147)
	// Расчет ИЗВ на заголовки
	GostStruct Cript;
	Cript.REGIM		= MAKE_IMZ;
	Cript.Key		= ikev2_sa->Kai;
	Cript.Din		= buffer;
	Cript.LenIMZ	= LEN_IMZ_8;
	Cript.Dout		= izv;
	Cript.LenBytes	= 40;
	Cript.TR_STATE	= TR_NO;
	Cript.Tz		= (unsigned char *)ikev2_sa->blockNote.Table;
	Gost28147(&Cript);
#elif defined(CRYPT_MAGMA)
	unsigned char imit_ctx[kImit89ContextLen];
	if(!cypher_magma_imit_init((unsigned char *)ikev2_sa->Kai, LEN_IMZ_8, imit_ctx))
		goto error;
	if(!cypher_imit(imit_ctx, buffer, izv, 40))
		goto error;
	free_imit(imit_ctx);
#endif

	memcpy((buffer + 40), izv, 8);

    /* Данные для шифрования */
    //ID
    *(unsigned char *)(buffer  + 48)		= ikev2_np_auth;			// Next Payload
    *(unsigned char *)(buffer  + 49)		= 0;
    *(unsigned short *)(buffer + 50)		= reverse16(ikev2_SIZE_ID_H);	//Len
    *(unsigned char *)(buffer  + 52)		= 201;						//ID Type
    *(unsigned short *)(buffer + 53)		= 0;
    *(unsigned char *)(buffer  + 55)		= 0;
    memcpy((buffer + 56), ikev2_sa->blockNote.name, 8);
    memcpy((buffer + 64), ikev2_sa->blockNote.Nserial, 8);
    memcpy((buffer + 72), (unsigned char *)&ikev2_sa->blockNote.numOfKompl, 2);
    memcpy((buffer + 74), (unsigned char *)&ikev2_sa->blockNote.NKompl, 2);

	// Блок AUTH
	*(unsigned char *)(buffer + 76)		= ikev2_np_sa;			// Next Payload
	*(unsigned char *)(buffer + 77)		= 0;
	*(unsigned short *)(buffer + 78)	= reverse16(ikev2_SIZE_AUTH_H);	//Len
	*(unsigned char *)(buffer + 80)		= 201;						//Auth Method
	*(unsigned short *)(buffer + 81)	= 0;
	*(unsigned char *)(buffer + 83)		= 0;

	//Генерация ESP_SPI
    ikev2_sa->espInitSPI = (unsigned int)((*(unsigned int *)(ikev2_sa->initSPI + 4) & 0xFFFF) | ((*(unsigned int *)(ikev2_sa->respSPI+4)& 0xFFFF0000)));

	//Расчет AUTHi
	memset(temp, 0 , 32);
	memcpy(temp  , ikev2_sa->initSPI, 8);
	memcpy(temp+8, ikev2_sa->respSPI, 8);
	memcpy(temp+16, (unsigned char *)&ikev2_sa->espInitSPI, 4);
	temp[20] = 1;
	
#if defined(CRYPT_GOST28147)	
	Cript.REGIM		= MAKE_IMZ;
	Cript.Key		= ikev2_sa->Kai;
	Cript.LenIMZ	= LEN_IMZ_4;
	Cript.Din		= temp;
	Cript.Dout		= (unsigned char *)&A[0];
	Cript.LenBytes	= 24;
	Cript.TR_STATE	= 0;
	Cript.Tz		= (unsigned char *)ikev2_sa->blockNote.Table;
	Gost28147(&Cript);
#elif defined(CRYPT_MAGMA)
	if(!cypher_magma_imit_init((unsigned char *)ikev2_sa->Kai, LEN_IMZ_4, imit_ctx))
		goto error;
	if(!cypher_imit(imit_ctx, temp,(unsigned char *)&A[0], 24))
		goto error;
	free_imit(imit_ctx);
#endif

	memcpy(temp+4, ikev2_sa->initSPI, 8);
	memcpy(temp+12, ikev2_sa->respSPI, 8);
	memcpy(temp+20, (unsigned char *)&ikev2_sa->espInitSPI, 4);

	for(int i = 1; i < 4; i++) {
		memcpy(temp  , (unsigned char *)&A[i-1], 4);
		temp[24] = i+1;
#if defined(CRYPT_GOST28147)	
		Cript.Din		= temp;
		Cript.Dout		= (unsigned char *)&A[i];
		Cript.LenBytes	= 32;
		Cript.TR_STATE	= 0;
		Cript.Tz		= (unsigned char *)ikev2_sa->blockNote.Table;
		Gost28147(&Cript);
#elif defined(CRYPT_MAGMA)
		if(!cypher_magma_imit_init((unsigned char *)ikev2_sa->Kai, LEN_IMZ_4, imit_ctx))
			goto error;
		if(!cypher_imit(imit_ctx, temp,(unsigned char *)&A[i], 32))
			goto error;
		free_imit(imit_ctx);
#endif
	}

	memcpy((buffer + 84),A,16);

	// Блок SA
	*(unsigned char *)(buffer + 100)		= ikev2_np_TSi;										// Next Payload
	*(unsigned char *)(buffer + 101)		= 0;
	*(unsigned short *)(buffer + 102)		= reverse16((ikev2_SIZE_TRANSFORM_H * ikev2_sa->proposals->num_transf) * ikev2_sa->num_prop + ikev2_SIZE_PROPOSAL_H + 4 + 4);

	//Proposals
	*(unsigned char *)(buffer + 104)		= 0;												// last
	*(unsigned char *)(buffer + 105)		= 0;												//RESERVED
	*(unsigned short *)(buffer + 106)		= reverse16((ikev2_SIZE_TRANSFORM_H * ikev2_sa->proposals->num_transf) * ikev2_sa->num_prop + ikev2_SIZE_PROPOSAL_H + 4);  //len
	*(unsigned char *)(buffer + 108)		= 1;												//Переписать формирование массива !!!
	*(unsigned char *)(buffer + 109)		= 3;												//Protocol ID
	*(unsigned char *)(buffer + 110)		= 4;												//SPI size
	*(unsigned char *)(buffer + 111)		= ikev2_sa->proposals->num_transf;

	*(unsigned int *)(buffer + 112)			= ikev2_sa->espInitSPI;								// Init SPI ESP

	//Transforms
	*(unsigned char *)(buffer + 116)		= 3;												//more
	*(unsigned char *)(buffer + 117)		= 0;												//RESERVED
	*(unsigned short *)(buffer + 118)		= reverse16(ikev2_SIZE_TRANSFORM_H);				//len
	*(unsigned char *)(buffer + 120)		= ikev2_sa->proposals->transforms[0].type;			//Transform Type
	*(unsigned char *)(buffer + 121)		= 0;												//RESERVED
	*(unsigned short *)(buffer + 122)		= reverse16(ikev2_sa->proposals->transforms[0].id);	//Transform ID

	*(unsigned char *)(buffer + 124)		= 0;												//last
	*(unsigned char *)(buffer + 125)		= 0;												//RESERVED
	*(unsigned short *)(buffer + 126)		= reverse16(ikev2_SIZE_TRANSFORM_H);				//len
	*(unsigned char *)(buffer + 128)		= ikev2_sa->proposals->transforms[1].type;			//Transform Type
	*(unsigned char *)(buffer + 129)		= 0;												//RESERVED
	*(unsigned short *)(buffer + 130)		= reverse16(ikev2_sa->proposals->transforms[1].id); //Transform ID


	//Блок TSi
	*(unsigned char *)(buffer + 132)		= ikev2_np_TSr;			// Next Payload
	*(unsigned char *)(buffer + 133)		= 0;
	*(unsigned short *)(buffer + 134)		= reverse16(24);		// Len
	*(unsigned char *)(buffer + 136)		= 1;					// Number of TSs
	*(unsigned short *)(buffer + 137)		= 0;
	*(unsigned char *)(buffer + 139)		= 0;

	// Trafic Selector	
	*(unsigned char *)(buffer + 140)		= 7;					// TS type  (TS_IPV4_ADDR_RANGE)
	*(unsigned char *)(buffer + 141)		= 0;					// IP Protocol ID (0 - ID протокола не важен)
	*(unsigned short *)(buffer + 142)		= reverse16(16);		// Selector Len
	*(unsigned short *)(buffer + 144)		= 0;					// Start port
	*(unsigned short *)(buffer + 146)		= 0xFFFF;				// End port
	*(unsigned int *)(buffer + 148)			= 0;					// Starting address
	*(unsigned int *)(buffer + 152)			= 0xFFFFFFFF;			// Ending address

	//Блок TSr
	*(unsigned char *)(buffer + 156)		= ikev2_np_not;			// Next Payload
	*(unsigned char *)(buffer + 157)		= 0;
	*(unsigned short *)(buffer + 158)		= reverse16(24);		// Len
	*(unsigned char *)(buffer + 160)		= 1;					// Number of TSs
	*(unsigned short *)(buffer + 161)		= 0;
	*(unsigned char *)(buffer + 163)		= 0;

	// Trafic Selector	
	*(unsigned char *)(buffer + 164)		= 7;					// TS type  (TS_IPV4_ADDR_RANGE)
	*(unsigned char *)(buffer + 165)		= 0;					// IP Protocol ID (0 - ID протокола не важен)
	*(unsigned short *)(buffer + 166)		= reverse16(16);		// Selector Len
	*(unsigned short *)(buffer + 168)		= 0;					// Start port
	*(unsigned short *)(buffer + 170)		= 0xFFFF;				// End port
	*(unsigned int *)(buffer + 172)			= 0;					// Starting address
	*(unsigned int *)(buffer + 176)			= 0xFFFFFFFF;			// Ending address

    for(int i = 1; i <= lenPad; i++) {
        buffer[*len_data_out - 9 - (lenPad + 1 - i)] = i;
    }

	*(buffer + (*len_data_out - 9))		= lenPad;

#if defined(CRYPT_GOST28147)
	// Расчет имитовставки
	Cript.REGIM		= MAKE_IMZ;
	Cript.Key		= ikev2_sa->Kei;
	Cript.LenIMZ	= LEN_IMZ_8;
	Cript.Din		= buffer + 48;
	Cript.Dout		= buffer + (*lenDataOut - 8);
	Cript.LenBytes	= lenPad + lenCriptoData + lenPadLength;
	Cript.TR_STATE	= TR_NO;
	Cript.Tz		= (unsigned char *)ikev2_sa->blockNote.Table;
	Gost28147(&Cript);

	// Шифрование
	Cript.REGIM	= GAMMIROVANIE_OS_REG;
	Cript.CRYPT	= ENCRYPT;
	Cript.Key	= ikev2_sa->Kei;
	Cript.Sp	= (unsigned int *)(buffer + 32);
	Cript.Din	= buffer + 48;
	Cript.Dout	= buffer + 48;
	Cript.LenBytes = lenPad + lenCriptoData + lenPadLength;
	Cript.TR_STATE = TR_NO;
	Cript.Tz		= (unsigned char *)ikev2_sa->blockNote.Table;
	Gost28147(&Cript);
#elif defined(CRYPT_MAGMA)
	if(!cypher_magma_imit_init((unsigned char *)ikev2_sa->Kei, LEN_IMZ_8, imit_ctx))
		goto error;

	int len_temp_buf = 8;
	unsigned char * temp_buffer = (unsigned char * )malloc(len_temp_buf);
	if(!cypher_imit(imit_ctx, buffer + 48, temp_buffer, lenPad + lenCriptoData + lenPadLength))
		goto error;
	memcpy(buffer + (*len_data_out - 8), temp_buffer, len_temp_buf);
	free(temp_buffer);
	free_imit(imit_ctx);

	unsigned char ctx[kCfb89ContextLen];
	if(!cypher_magma_cfb_init((unsigned char *)ikev2_sa->Kei, ctx, kBlockLen89, buffer + 32, 8))
		goto error;

	len_temp_buf = lenPad + lenCriptoData + lenPadLength;
	temp_buffer = (unsigned char * )malloc(len_temp_buf);
	if(!cypher_encr_cfb(ctx, buffer + 48, temp_buffer, len_temp_buf))
		goto error;
	memcpy(buffer + 48, temp_buffer, len_temp_buf);
	free(temp_buffer);
	free_cfb(ctx);
#endif

	ikev2_sa->stage = IKE_STAGE_3;
    *len_data_out += ikev2_SIZE_START_ZERO;
    buffer -= ikev2_SIZE_START_ZERO;
    *data_out = buffer;
    return;

	error:
	*len_data_out = 0;
	*data_out = NULL;
	if(buffer != NULL)
	    free(buffer);
	return;
}

/**
 * Функция генерации сообщения KEEPALIVE
 * @param data_out
 * @param len_data_out
 * @param sa
 */
void ikev2_get_keepalive(unsigned char ** data_out, int * len_data_out) {
	unsigned char * buffer = NULL;

	IKEv2_STRUCT_SA * ikev2_sa = ikev2_sa_pull[index_main_ikev2_sa].ikev2_sa;

	if(ikev2_sa == NULL || ikev2_sa->stage != IKE_STAGE_4) {
		*len_data_out = 0;
		return;
	}

	buffer = (unsigned char *)malloc(ikev2_SIZE_HDR + 4 + ikev2_SIZE_START_ZERO);
	memset(buffer, 0, ikev2_SIZE_HDR + 4 + ikev2_SIZE_START_ZERO);
	buffer += ikev2_SIZE_START_ZERO;
	memcpy(buffer, ikev2_sa->initSPI, 8);
	memcpy(buffer+8, ikev2_sa->respSPI, 8);

	*(buffer + 16)						= ikev2_np_SK;
	*(buffer + 17)						= 0x20;
	*(buffer + 18)						= INFORMATIONAL;
	*(buffer + 19)						= 0x08;
	*(unsigned int*)(buffer +20)		= reverse32(ikev2_sa->outMessageID);
	*(unsigned int*)(buffer +24)		= reverse32(ikev2_SIZE_HDR+4);
	*(buffer + 28)                      = ikev2_np_not;
	*(buffer + 29)                      = 0;
	*(unsigned short *)(buffer +30)		= reverse16(4);

	ikev2_sa->outMessageID++;
	buffer -= ikev2_SIZE_START_ZERO;
	*len_data_out = ikev2_SIZE_HDR + 4 + ikev2_SIZE_START_ZERO;
	*data_out = buffer;
}


/**
 * Функция генерации сообщения удаления контекста
 * @param data_out
 * @param len_data_out
 * @param sa
 */
void ikev2_get_ike_delete(unsigned char ** data_out, int * len_data_out) {
	int sizeBlockCrypto, lenCryptoData;
	int lenPadLength;
	unsigned char lenPad;
	unsigned char izv[LEN_IMZ_8];
	unsigned char * buffer = NULL;

	IKEv2_STRUCT_SA * ikev2_sa = ikev2_sa_pull[index_main_ikev2_sa].ikev2_sa;

	if(ikev2_sa->stage != IKE_STAGE_4) {
		*len_data_out = 0;
		*data_out = NULL;
		return;
	}

	//Подсчет длины всего сообщения
	lenCryptoData = 8; // Размер данных равен размеру блока Delete. Он всегда одинаковый
	sizeBlockCrypto = 8;
	lenPadLength = 1;
	lenPad = (sizeBlockCrypto -  (lenCryptoData + lenPadLength) % sizeBlockCrypto);

	*len_data_out = lenPad +
					lenCryptoData +
					ikev2_SIZE_SK_H +
					ikev2_SIZE_HDR +
					lenPadLength;

    buffer = (unsigned char *)malloc(*len_data_out+ikev2_SIZE_START_ZERO);
    memset(buffer, 0, ikev2_SIZE_START_ZERO);
    buffer += ikev2_SIZE_START_ZERO;

	//HDR
	memcpy(buffer, ikev2_sa->initSPI, 8);							// Init SPi
	memcpy(buffer+8, ikev2_sa->respSPI, 8);							// Resp SPI

	*(unsigned char *)(buffer + 16)		= ikev2_np_SK;				// Next Payload
	*(unsigned char *)(buffer + 17)		= 0x20;						// Ver
	*(unsigned char *)(buffer + 18)		= INFORMATIONAL;			// Exchange Type
	*(unsigned char *)(buffer + 19)		= 0x08;						// Flags
	*(unsigned int *)(buffer + 20)		= reverse32(ikev2_sa->outMessageID);// Message ID
	*(unsigned int *)(buffer + 24)		= reverse32(*len_data_out);

	//SK
	*(unsigned char *)(buffer + 28)		= ikev2_np_delete;			// Next Payload
	*(unsigned char *)(buffer + 29)		= 0;
	*(unsigned short *)(buffer + 30)	= reverse16(ikev2_SIZE_SK_H + lenCryptoData + lenPad + lenPadLength);
	*(unsigned int *)(buffer + 32)		= random();				//Initialization Vector
	*(unsigned int *)(buffer + 36)		= random();				//Initialization Vector
	
#if defined(CRYPT_GOST28147)
	// Расчет ИЗВ на заголовки
	GostStruct Cript;
	Cript.REGIM		= MAKE_IMZ;
	Cript.Key		= ikev2_sa->Kai;
	//Cript.Tz		= TZ;
	Cript.Din		= buffer;
	Cript.LenIMZ	= LEN_IMZ_8;
	Cript.Dout		= izv;
	Cript.LenBytes	= 40;
	Cript.TR_STATE	= 0;
	Cript.Tz		= (unsigned char *)ikev2_sa->blockNote.Table;
	Gost28147(&Cript);
#elif defined(CRYPT_MAGMA)
	unsigned char imit_ctx[kImit89ContextLen];
	if(!cypher_magma_imit_init((unsigned char *)ikev2_sa->Kai, LEN_IMZ_8, imit_ctx))
		goto error;
	if(!cypher_imit(imit_ctx, buffer, izv, 40))
		goto error;
	free_imit(imit_ctx);
#endif
	memcpy((buffer + 40), izv, 8);

	*(unsigned char *)(buffer + 48)		= ikev2_np_not;			// Next Payload
	*(unsigned char *)(buffer + 49)		= 0;
	*(unsigned short *)(buffer + 50)	= reverse16(8);	//Len
	*(unsigned char *)(buffer + 52)		= 1;
	*(unsigned char *)(buffer + 53)		= 0;
	*(unsigned short *)(buffer + 55)	= 0;
	
#if defined(CRYPT_GOST28147)
	Cript.REGIM		= MAKE_IMZ;
	Cript.Key		= ikev2_sa->Kei;
	Cript.LenIMZ	= LEN_IMZ_8;
	Cript.Din		= (unsigned char *)(buffer + 48);
	Cript.Dout		= buffer + (*len_data_out - 8);
	Cript.LenBytes	= lenPad + lenCryptoData + lenPadLength;
	Cript.TR_STATE	= 0;
	Cript.Tz		= (unsigned char *)ikev2_sa->blockNote.Table;
	Gost28147(&Cript);

	// Шифрование
	Cript.REGIM	= GAMMIROVANIE_OS_REG;
	Cript.CRYPT	= ENCRYPT;
	Cript.Key	= ikev2_sa->Kei;
	Cript.Sp	= (unsigned int *)(buffer + 32);
	Cript.Din	= (unsigned char *)(buffer + 48);
	Cript.Dout	= (unsigned char *)(buffer + 48);
	Cript.LenBytes = lenPad + lenCryptoData + lenPadLength;
	Cript.TR_STATE = 0;
	Cript.Tz	= (unsigned char *)ikev2_sa->blockNote.Table;
	Gost28147(&Cript);
#elif defined(CRYPT_MAGMA)
	if(!cypher_magma_imit_init((unsigned char *)ikev2_sa->Kei, LEN_IMZ_8, imit_ctx))
		goto error;
	if(!cypher_imit(imit_ctx, buffer + 48, buffer + (*len_data_out - 8), lenPad + lenCryptoData + lenPadLength))
		goto error;
	free_imit(imit_ctx);

	unsigned char ctx[kCfb89ContextLen];
	if(!cypher_magma_cfb_init((unsigned char *)ikev2_sa->Kei, ctx, kBlockLen89, buffer + 32, 8))
		goto error;

	int len_temp_buf = lenPad + lenCryptoData + lenPadLength;
	unsigned char * temp_buffer = (unsigned char * )malloc(len_temp_buf);
	if(!cypher_encr_cfb(ctx, buffer + 48, temp_buffer, len_temp_buf))
		goto error;
	memcpy(buffer + 48, temp_buffer, len_temp_buf);
	free(temp_buffer);
	free_cfb(ctx);
#endif

    *len_data_out += ikev2_SIZE_START_ZERO;
    buffer -= ikev2_SIZE_START_ZERO;
    *data_out = buffer;
	return;

	error:
	*len_data_out = 0;
	*data_out = NULL;
	if(buffer != NULL)
	    free(buffer);
}

/**
 *	Функция получения пакета запроса настроек центрального шифратора
 *	Не генерирует пакет если сессия не установлена или настройки уже были ранее получены
 *
 *
 *
 */


void ikev2_get_network_settings(unsigned char ** dataOut, int * lenDataOut) {
	unsigned int sizeBlockCripto, lenCryptoData;
	unsigned int lenPadLength, lenIKEMessage;
	unsigned char lenPad;
	unsigned char izv[8];
	unsigned char * buffer = NULL;
	IKEv2_STRUCT_SA * ikev2_sa = ikev2_sa_pull[index_main_ikev2_sa].ikev2_sa;

	if(ikev2_sa->stage != IKE_STAGE_4) {
		*lenDataOut = 0;
		return;
	}

	lenCryptoData = ikev2_SIZE_NOTIFY_H;		// Подсчет длины зашифрованных данных
	sizeBlockCripto = 8;						// Размер блока шифрования
	lenPadLength = 1;							// Размер (в байтах) поля Pad Length в блоке SK
	lenPad = (sizeBlockCripto - (lenCryptoData + lenPadLength) % sizeBlockCripto);

	lenIKEMessage = ikev2_SIZE_HDR +
			        ikev2_SIZE_SK_H +
					lenCryptoData +
					lenPad +
				  	lenPadLength;

	buffer = (unsigned char *)malloc(lenIKEMessage + ikev2_SIZE_START_ZERO);
	memset(buffer, 0, ikev2_SIZE_START_ZERO);
	buffer += ikev2_SIZE_START_ZERO;

	// HDR
	memcpy(buffer, ikev2_sa->initSPI, 8);
	memcpy(buffer+8, ikev2_sa->respSPI, 8);
	*(buffer + 16)						= ikev2_np_SK;
	*(buffer + 17)						= 0x20;
	*(buffer + 18)						= INFORMATIONAL;
	*(buffer + 19)						= 0x08;
	*(unsigned int*)(buffer +20)		= reverse32(ikev2_sa->outMessageID);
	*(unsigned int*)(buffer +24)		= reverse32(lenIKEMessage);

	// SK
	*(buffer + 28)                      = ikev2_np_notify;
	*(buffer + 29)                      = 0;
	*(unsigned short *)(buffer +30)		= reverse16(ikev2_SIZE_SK_H + lenCryptoData + lenPad + lenPadLength);

	//*(unsigned int *)(buffer + 32)		= random();				//Initialization Vector
	//*(unsigned int *)(buffer + 36)		= random();				//Initialization Vector
	memcpy(buffer + 32, get_random(ikev2_sa->SecureIdentifyInf), 8);

#if defined(CRYPT_GOST28147)
	// Расчет имитовставки на заголовки
	GostStruct Cript;
	Cript.REGIM		= MAKE_IMZ;
	Cript.Key		= ikev2_sa->Kai;
	Cript.Din		= buffer;
	Cript.LenIMZ	= LEN_IMZ_8;
	Cript.Dout		= izv;
	Cript.LenBytes	= ikev2_SIZE_HDR + 12;
	Cript.TR_STATE	= 0;
	Cript.Tz		= (unsigned char *)ikev2_sa->blockNote.Table;
	Gost28147(&Cript);
#elif defined(CRYPT_MAGMA)
	unsigned char imit_ctx[kImit89ContextLen];
	if(!cypher_magma_imit_init((unsigned char *)ikev2_sa->Kai, LEN_IMZ_8, imit_ctx))
		goto error;
	if(!cypher_imit(imit_ctx, buffer, izv, ikev2_SIZE_HDR + 12))
		goto error;
	free_imit(imit_ctx);
#endif

	memcpy((buffer + 40), izv, 8); 		//Integrity Checksum Data 1


	// NOTIFY
	*(buffer + 48)                       	= ikev2_np_not;		// Next Payload
	*(buffer + 49)                       	= 0;				// Reserved
	*(unsigned short *)(buffer +50)			= 8;				// Payload Length
	*(buffer + 52)							= 1;				// Protocol ID
	*(buffer + 53)                       	= 0;				// SPI Size
	*(unsigned short *)(buffer +54)			= reverse16(GET_NETWORK_SETTINGS);				// Notify Message Type

    for(int i = 1; i <= lenPad; i++) {
        buffer[lenIKEMessage - 9 - (lenPad + 1 - i)] = i;
    }

	*(buffer + (lenIKEMessage - 9))		= lenPad;

#if defined(CRYPT_GOST28147)
	// Расчет имитовставки
	Cript.REGIM		= MAKE_IMZ;
	Cript.Key		= ikev2_sa->Kei;
	Cript.LenIMZ	= LEN_IMZ_8;
	Cript.Din		= buffer + 52;
	Cript.Dout		= buffer + (lenIKEMessage - 8);
	Cript.LenBytes	= lenPad + lenCryptoData + lenPadLength;
	Cript.TR_STATE	= TR_NO;
	Cript.Tz		= (unsigned char *)ikev2_sa->blockNote.Table;
	Gost28147(&Cript);

	// Шифрование
	Cript.REGIM	= GAMMIROVANIE_OS_REG;
	Cript.CRYPT	= ENCRYPT;
	Cript.Key	= ikev2_sa->Kei;
	Cript.Sp	= (unsigned int *)(buffer + 32);
	Cript.Din	= buffer + 52;
	Cript.Dout	= buffer + 52;
	Cript.LenBytes = lenPad + lenCryptoData + lenPadLength;
	Cript.TR_STATE = TR_NO;
	Cript.Tz	= (unsigned char *)ikev2_sa->blockNote.Table;
	Gost28147(&Cript);
#elif defined(CRYPT_MAGMA)
	if(!cypher_magma_imit_init((unsigned char *)ikev2_sa->Kei, LEN_IMZ_8, imit_ctx))
		goto error;
	if(!cypher_imit(imit_ctx, buffer + 48, buffer + (lenIKEMessage - 8), lenPad + lenCryptoData + lenPadLength))
		goto error;
	free_imit(imit_ctx);

	unsigned char ctx[kCfb89ContextLen];
	if(!cypher_magma_cfb_init((unsigned char *)ikev2_sa->Kei, ctx, kBlockLen89, buffer + 32, 8))
		goto error;
	int len_temp_buf = lenPad + lenCryptoData + lenPadLength;
	unsigned char * temp_buffer = (unsigned char * )malloc(len_temp_buf);
	if(!cypher_encr_cfb(ctx, buffer + 48, temp_buffer, len_temp_buf))
		goto error;
	memcpy(buffer + 48, temp_buffer, len_temp_buf);
	free(temp_buffer);
	free_cfb(ctx);
#endif

	ikev2_sa->outMessageID++;
	buffer -= ikev2_SIZE_START_ZERO;
	*lenDataOut = lenIKEMessage + ikev2_SIZE_START_ZERO;
	*dataOut = buffer;
	return;

	error:
	*lenDataOut = 0;
	*dataOut = NULL;
	if(buffer != NULL)
	    free(buffer);
	return;
}


unsigned int reverse32(unsigned int a) {
	return ((a & 0xff000000) >> 24) | 
		   ((a & 0x00ff0000) >> 8) | 
		   ((a & 0x0000ff00) << 8) | 
		   ((a & 0x000000ff) << 24);
}

unsigned short reverse16(unsigned short a) {
	return ((a >> 8 & 0xFF) | (a << 8));
}

unsigned char check_ikesa_stage(IKEv2_STRUCT_SA * sa) {
	if(sa == NULL || sa->stage != IKE_STAGE_4)
		return IKE_ERR_STAGE;
	return IKE_OK;
}

int check_tsi_tsr( unsigned char protocol, unsigned char * inBuf, IKEv2_STRUCT_SA * ikev2_sa) {
    unsigned short srcPort;
    unsigned short dstPort;
    unsigned int srcIPAdr;
    unsigned int dstIPAdr;
    char flag;

	// Были ли получены селекторы трафика
	// Если нет, пропускаем пакет
    if(ikev2_sa->TSi == NULL || ikev2_sa->TSr == NULL) {
        return IKE_ERR_TS_NULL;
    }
    switch(protocol) {
        case IPV4 : {
			// В ip пакете извлекаются ip адреса, из UDP или TCP пакета порты
            srcPort = reverse16(*(unsigned short *)(inBuf + ((*inBuf) & 0x0F)*4));
            dstPort = reverse16(*(unsigned short *)(inBuf + ((*inBuf) & 0x0F)*4 + 2));
            srcIPAdr = reverse32(*(unsigned int *)(inBuf + 12));
            dstIPAdr = reverse32(*(unsigned int *)(inBuf + 16));

            // Проверка STi
			flag = 0;
            for(int i = 0; i < ikev2_sa->numSTi; i++) {
				if(srcPort >= ikev2_sa->TSi[i].startPort &&
				   srcPort <= ikev2_sa->TSi[i].endPort	 &&
				   srcIPAdr >= ikev2_sa->TSi[i].startAdd &&
				   srcIPAdr <= ikev2_sa->TSi[i].endAdd) {
					flag = 1;
					break;
				}
            }

			if(!flag) {
				return IKE_ERR_TSI_OVER;
			}

            // Проверка STr
			flag = 0;
            for(int i = 0; i < ikev2_sa->numSTr; i++) {
                if(dstPort >= ikev2_sa->TSr[i].startPort &&
				   dstPort <= ikev2_sa->TSr[i].endPort   &&
				   dstIPAdr >= ikev2_sa->TSr[i].startAdd &&
				   dstIPAdr <= ikev2_sa->TSr[i].endAdd) {
					flag = 1;
                    break;
                }
            }

			if(!flag) {
				return IKE_ERR_TSR_OVER;
			}

			break;
        }
        default : {
            return IKE_ERR_SUPPORT_ONLY_IPV4;
        }
    }

    return IKE_OK;
}

void createBlockHDRfromBuf(unsigned char * data, ikev2_block_HDR * block_HDR) {
	memcpy(block_HDR->initSPI, data, 8);
    memcpy(block_HDR->respSPI, data+8, 8);
	block_HDR->nextPayload	= *(data + 16);
	block_HDR->vers			= *(data + 17);
	block_HDR->exchangeType = *(data + 18);
	block_HDR->flags		= *(data + 19);
	block_HDR->messageID	= reverse32(*(unsigned int *)(data + 20));
	block_HDR->length		= reverse32(*(unsigned int *)(data + 24));
}

int createBlockSAfromBuf(unsigned char * data, int lenData, ikev2_block_SA * block_SA) {
	int result;
	int lenLast = lenData;
	if((lenLast - ikev2_SIZE_SA_H) < 0)
		return IKE_ERR_LEN;
	block_SA->nextPayload	= *data;
	block_SA->C				= *(data + 1);
	block_SA->length		= reverse16(*(unsigned short *)(data + 2));
	
	//Собираем из данных блоки Proposal
	if(result = createBlocksProposalFromBuf(data+4, block_SA->length - 4, &block_SA->proposals))
		return result;

	return IKE_OK;
}

int createBlocksProposalFromBuf(unsigned char * data, int lenData, ikev2_block_PROP ** proposals) {
	//Подсчет количесво блоков Proposals
	//С учетом отсутствия Transform Attributes !!!!!!!!!!!!!
	int numBlocks = 0;
	unsigned char * tempData = data;
	int result = IKE_OK;
	int index = 0;
	int lenLast = lenData;
	while(1){
		if(tempData[index] == 0) {
			numBlocks ++;
			break;
		}
		//Если предложение не последнее то точно не будет SPI для ESP
		if((lenLast - (ikev2_SIZE_PROPOSAL_H + tempData[7] * ikev2_SIZE_TRANSFORM_H)) <= 0)
			return IKE_ERR_LEN;
		index += ikev2_SIZE_PROPOSAL_H + tempData[7] * ikev2_SIZE_TRANSFORM_H;
		lenLast -= ikev2_SIZE_PROPOSAL_H + tempData[7] * ikev2_SIZE_TRANSFORM_H;
		numBlocks ++;
	}

	*proposals = (ikev2_block_PROP *)malloc(numBlocks * sizeof(ikev2_block_PROP));
	lenLast = lenData;

	for(int i = 0; i < numBlocks; i++) {
		if((lenLast - ikev2_SIZE_PROPOSAL_H - 4) <= 0)
			return IKE_ERR_LEN;
		(*proposals)[i].LorM		= *tempData;
		(*proposals)[i].reserved	= *(tempData + 1);
		(*proposals)[i].length		= reverse16(*(unsigned short *)(tempData+2));
		(*proposals)[i].number		= *(tempData+4);
		(*proposals)[i].id			= *(tempData+5);
		(*proposals)[i].SPIsize		= *(tempData+6);
		(*proposals)[i].numOfTransf	= *(tempData+7);
		if((*proposals)[i].SPIsize > 0 ) {
            (*proposals)[i].spi		= *(unsigned int*)(tempData+8);
            lenLast -= ikev2_SIZE_PROPOSAL_H + 4;
			if(result = createBlocksTransformsFromBuf(data+ikev2_SIZE_PROPOSAL_H + 4, lenLast, (*proposals)[i].numOfTransf, &(*proposals)[i].transforms))
				return result;
			tempData += (ikev2_SIZE_PROPOSAL_H  + 4 + ikev2_SIZE_TRANSFORM_H * (*proposals)[i].numOfTransf);
			lenLast -= (ikev2_SIZE_PROPOSAL_H  + 4 + ikev2_SIZE_TRANSFORM_H * (*proposals)[i].numOfTransf);
		}
		else {
			(*proposals)[i].spi = 0;
			lenLast -= ikev2_SIZE_PROPOSAL_H ;
			if(result = createBlocksTransformsFromBuf(data+ikev2_SIZE_PROPOSAL_H, lenLast, (*proposals)[i].numOfTransf, &(*proposals)[i].transforms))
				return result;
			tempData += (ikev2_SIZE_PROPOSAL_H + ikev2_SIZE_TRANSFORM_H * (*proposals)[i].numOfTransf);
			lenLast -= (ikev2_SIZE_PROPOSAL_H  + 4 + ikev2_SIZE_TRANSFORM_H * (*proposals)[i].numOfTransf);
		}
	}

	return IKE_OK;
}

int createBlocksTransformsFromBuf(unsigned char * data, int lenData, int numTransforms, ikev2_block_TRANSF ** transforms){
	
	int lenLast = lenData;
	unsigned char * tempData = data;
	if((lenLast - (numTransforms * ikev2_SIZE_TRANSFORM_H)) < 0)
		return IKE_ERR_LEN;

	*transforms = (ikev2_block_TRANSF *)malloc(numTransforms * sizeof(ikev2_block_TRANSF));

	for(int i = 0; i < numTransforms; i++) {
		(*transforms)[i].LorM		= *tempData;
		(*transforms)[i].reserved0	= *(tempData + 1);
		(*transforms)[i].length		= reverse16(*(unsigned short *)(tempData+2));
		(*transforms)[i].type		= *(tempData+4);
		(*transforms)[i].reserved1	= *(tempData+5);
		(*transforms)[i].id			= reverse16(*(unsigned short *)(tempData+6));

		tempData += ikev2_SIZE_TRANSFORM_H;
	}

	return IKE_OK;
}

int createBlockKEfromBuf(unsigned char * data, int lenData, ikev2_block_KE * block_KE) {
	int lenLast = lenData;
	if((lenLast - ikev2_SIZE_KE_H) < 0)
		return IKE_ERR_LEN;

	block_KE->nextPayload	= *data;
	block_KE->C				= *(data + 1);
	block_KE->length		= reverse16(*(unsigned short *)(data + 2));
	block_KE->DH_Group		= reverse16(*(unsigned short *)(data + 4));
	block_KE->reserved		= reverse16(*(unsigned short *)(data + 6));
	block_KE->KE_Data		= (data + 8);

	// Проверка блока KE
	if(block_KE->nextPayload != ikev2_np_nonce)
		return IKE_ERR_KE_NP;

	if(block_KE->DH_Group != 1024)
		return IKE_ERR_KE_DHG;

	return IKE_OK;
}

int createBlockNoncefromBuf(unsigned char * data, int lenData, ikev2_block_NONCE * block_Nonce) {
	int lenLast = lenData;
	if((lenLast - ikev2_SIZE_NONCE_H) < 0)
		return IKE_ERR_LEN;

	block_Nonce->nextPayload	= *data;
	block_Nonce->C				= *(data + 1);
	block_Nonce->length			= reverse16(*(unsigned short *)(data + 2));
	block_Nonce->N_Data			= (data + 4);

	return IKE_OK;
}

int createBlockNotifyfromBuf(unsigned char * data, int lenData, ikev2_block_NOTIFY * block_Notify) {
	int lenLast = lenData;
	if((lenLast - 8) < 0)
		return IKE_ERR_LEN;

	block_Notify->nextPayload		= *data;
	block_Notify->C					= *(data + 1);
	block_Notify->length			= reverse16(*(unsigned short *)(data + 2));
	block_Notify->protocolID		= *(data + 4);
	block_Notify->sizeSPI			= *(data + 5);
	block_Notify->notifyMessageType	= reverse16(*(unsigned short *)(data + 6));
	lenLast -= 8;
	if(block_Notify->sizeSPI > 0) {
		if((lenLast - block_Notify->sizeSPI) < 0)
			return IKE_ERR_LEN;

		block_Notify->spi = (unsigned char *)malloc(block_Notify->sizeSPI);
		memcpy(block_Notify->spi, data + 8, block_Notify->sizeSPI);

		lenLast -= block_Notify->sizeSPI;
		if((lenLast - (block_Notify->length - (block_Notify->sizeSPI + 8))) < 0)
			return IKE_ERR_LEN;

		block_Notify->Notify_Data = (unsigned char *)malloc(block_Notify->length - (block_Notify->sizeSPI + 8));
		memcpy(block_Notify->Notify_Data, data + 8 + block_Notify->sizeSPI, block_Notify->length - (block_Notify->sizeSPI + 8));
	}
	else {
		if(lenLast - (block_Notify->length - 8) < 0)
			return IKE_ERR_LEN;

		block_Notify->Notify_Data = (unsigned char *)malloc(block_Notify->length - 8);
		memcpy(block_Notify->Notify_Data, data + 8, block_Notify->length - 8);
	}

	return IKE_OK;
}

int createBlockVendorIDfromBuf(unsigned char * data, int lenData, ikev2_block_VendorID * block_VendorID) {
	int lenLast = lenData;
	if((lenLast - 8) < 0)
		return IKE_ERR_LEN;

	block_VendorID->nextPayload		= *data;
	block_VendorID->C				= *(data + 1);
	block_VendorID->length			= reverse16(*(unsigned short *)(data + 2));
	block_VendorID->id				= data + 4;
	
	return IKE_OK;
}

int createBlockSKfromBuf(unsigned char * data, int lenData, ikev2_block_SK * block_SK) {
	int lenLast = lenData;
	block_SK->nextPayload	= *data;
	block_SK->C				= *(data + 1);
	block_SK->length		= reverse16(*(unsigned short *)(data + 2));
	memcpy(block_SK->VI, data+4, 8);
	memcpy(block_SK->IZV, data+12, 8);
	if((lenLast - block_SK->length) < 0)
		return IKE_ERR_LEN;
	block_SK->encrData		= (data + 20);
	memcpy(block_SK->IMZ, data + block_SK->length - 8, 8);
	return IKE_OK;
}

int createBlockIDfromBuf(unsigned char * data, int lenData, ikev2_block_IDENT * block_IDENT) {
	int lenLast = lenData;
	if((lenLast - ikev2_SIZE_ID_H) < 0)
		return IKE_ERR_LEN;

	block_IDENT->nextPayload	= *data;
	block_IDENT->C				= *(data + 1);
	block_IDENT->length			= reverse16(*(unsigned short *)(data + 2));
	block_IDENT->idType			= *(data + 4);
	block_IDENT->reserver0		= *(data + 5);
	block_IDENT->reserver1		= *(unsigned short *)(data + 6);
	block_IDENT->ID_Data		= data + 8;

	if((lenLast - block_IDENT->length) < 0)
		return IKE_ERR_LEN;

	return IKE_OK;
}

int createBlockAUTHfromBuf(unsigned char * data, int lenData, ikev2_block_AUTH * block_AUTH) {
	int lenLast = lenData;
	if((lenLast - ikev2_SIZE_ID_H) < 0)
		return IKE_ERR_LEN;
	
	block_AUTH->nextPayload		= *data;
	block_AUTH->C				= *(data + 1);
	block_AUTH->length			= reverse16(*(unsigned short *)(data + 2));
	block_AUTH->A_Method		= *(data + 4);
	block_AUTH->reserver0		= *(data + 5);
	block_AUTH->reserver1		= *(unsigned short *)(data + 6);
	block_AUTH->A_Data			= (data + 8);

	if((lenLast - block_AUTH->length) < 0)
		return IKE_ERR_LEN;

	return IKE_OK;
}

int createBlockCPfromBuf(unsigned char * data, int lenData, ikev2_block_CP * block_CP){
	int lenLast = lenData;
	if((lenLast - 24) < 0)
		return IKE_ERR_LEN;
	
	block_CP->nextPayload		= *data;
	block_CP->C					= *(data + 1);
	block_CP->length			= reverse16(*(unsigned short *)(data + 2));
	block_CP->CFG_Type			= *(data + 4);
	block_CP->reserver0			= *(data + 5);
	block_CP->reserver1			= *(unsigned short *)(data + 6);
	block_CP->A_Type1			= reverse16(*(unsigned short *)(data + 8));
	block_CP->A_Type1_length	= reverse16(*(unsigned short *)(data + 10));
	block_CP->value1			= reverse32(*(unsigned int *)(data + 12));
	block_CP->A_Type2			= reverse16(*(unsigned short *)(data + 16));
	block_CP->A_Type2_length	= reverse16(*(unsigned short *)(data + 18));
	block_CP->value2			= reverse32(*(unsigned int *)(data + 20));

	return IKE_OK;
}

int createBlockTRAFSELECTSfromBuf(unsigned char * data, int lenData, ikev2_block_TRAF_SELECTS * block_TRAF_SELECTS) {
	int lenLast = lenData;
	if((lenLast - 8) < 0)
		return IKE_ERR_LEN;

	block_TRAF_SELECTS->nextPayload		= *data;
	block_TRAF_SELECTS->C				= *(data + 1);
	block_TRAF_SELECTS->length			= reverse16(*(unsigned short *)(data + 2));
	block_TRAF_SELECTS->numOfTSs		= *(data + 4);
	block_TRAF_SELECTS->reserver0		= *(data + 5);
	block_TRAF_SELECTS->reserver1		= *(data + 6);
	block_TRAF_SELECTS->ID_Data 		= (ikev2_block_TRAF_SELECT *)malloc(sizeof(ikev2_block_TRAF_SELECT) * block_TRAF_SELECTS->numOfTSs);
	data = (data + 8);

	lenLast -= 8;
	if((lenLast - 16 * block_TRAF_SELECTS->numOfTSs) < 0)
		return IKE_ERR_LEN;
	for(int i = 0; i < block_TRAF_SELECTS->numOfTSs; i++) {
		block_TRAF_SELECTS->ID_Data[i].TS_Type 		= *(data + (i * 16));
		block_TRAF_SELECTS->ID_Data[i].IP_ID		= *(data + (i * 16) + 1);
		block_TRAF_SELECTS->ID_Data[i].length		= reverse16(*(unsigned short*)(data + (i * 16) + 2));
		block_TRAF_SELECTS->ID_Data[i].start_port	= reverse16(*(unsigned short *)(data + (i * 16) + 4));
		block_TRAF_SELECTS->ID_Data[i].end_port		= reverse16(*(unsigned short *)(data + (i * 16) + 6));
		block_TRAF_SELECTS->ID_Data[i].start_address	= reverse32(*(unsigned int *)(data + (i * 16) + 8));
		block_TRAF_SELECTS->ID_Data[i].end_address		= reverse32(*(unsigned int *)(data + (i * 16) + 12));
	}
	return IKE_OK;
}

int createBlockDeletefromBuf(unsigned char * data, int lenData, ikev2_block_DELETE * block_DELETE) {
    int lenLast = lenData;
    unsigned char * spis;
    if((lenLast - 8) < 0)
        return IKE_ERR_LEN;

    block_DELETE->nextPayload		= *data;
    block_DELETE->C				    = *(data + 1);
    block_DELETE->length			= reverse16(*(unsigned short *)(data + 2));
    block_DELETE->protocolID        = *(data + 4);
    block_DELETE->sizeSPI           = *(data + 5);
    block_DELETE->numOfSPIs         = reverse16(*(unsigned short *)(data + 6));

    if(block_DELETE->numOfSPIs > 0) {
        lenLast -= 8;
        if ((lenLast - (block_DELETE->sizeSPI * block_DELETE->numOfSPIs)) < 0)
            return IKE_ERR_LEN;

        block_DELETE->SPI = (unsigned char*)malloc(block_DELETE->sizeSPI * block_DELETE->numOfSPIs);
        int curentSPI;
        spis = data + 8;
        for(int i = 0; i < block_DELETE->numOfSPIs; i++) {
            curentSPI = block_DELETE->sizeSPI * i;
            for(int j = 0; j < block_DELETE->sizeSPI; j++) {
                block_DELETE->SPI[curentSPI+j] = spis[curentSPI+j];
            }
        }
    }
    return IKE_OK;
}


/*
 * Функция обработки пакетов IKEv2, полученных из сети
 * Вход:
 * dataIn - указатель на начало пакета IKEv2 (первые 4 нуля уже должны бить отброшены)
 * len_data_in - размер массива dataIn
 * Выход:
 * data_out - указатель на массив результата работы функции
 * len_data_out - размер массива data_out
 * err - содержит код результата работы функции
 */

int ikev2_processing_data(unsigned char * data_in, int len_data_in, unsigned char ** data_out, int * len_data_out) {
	int len_last = len_data_in;
    int result = IKE_OK;
	ikev2_block_HDR block_HDR;
	IKEv2_STRUCT_SA * ikev2_sa = NULL;

	*len_data_out = 0;

	// Проверка блока HDR
	if((len_last - ikev2_SIZE_HDR) >= 0) {
		createBlockHDRfromBuf(data_in, &block_HDR);
	}

	if(block_HDR.length > len_last)
		return IKE_ERR_LEN;

	len_last = block_HDR.length;
	len_last -= ikev2_SIZE_HDR;

	for(int i = 0; i < 2; i++) {
		if(ikev2_sa_pull[i].ikev2_sa != NULL) {
			if(!memcmp(block_HDR.initSPI, ikev2_sa_pull[i].ikev2_sa->initSPI, 8)) {
				ikev2_sa = ikev2_sa_pull[i].ikev2_sa;
				break;
			}
		}
	}

	if (ikev2_sa == NULL) {
		*data_out = NULL;
		*len_data_out = 0;
		return IKE_ERR_STAGE;
	}
	
	// Дальнейшая обработка зависит от типа Обмена
	switch(block_HDR.exchangeType) {
	case IKE_SA_INIT: {
        if(!memcmp(block_HDR.initSPI, ikev2_sa->initSPI, 8)){
            if(result = ikev2_check_ike_sa_init(data_in + ikev2_SIZE_HDR, len_last, ikev2_sa)) {
                return result;
            }
            // Добавить проверку ikev2_sa->stage == IKE_STAGE_4
            ikev2_sa->stage = IKE_STAGE_2;
            memcpy(ikev2_sa->respSPI, block_HDR.respSPI, 8);
            ikev2_get_ike_auth(data_out, len_data_out, ikev2_sa);
            result = IKE_SEND;
        } else {
            // Проверка пакета INIT для дополнительных соединений
            if(result = mmt_check_ike_sa_a_init(data_in, len_data_in, data_out, len_data_out)) {
                return result;
            }
			result = IKE_SEND;
        }
		break;
	}
	case IKE_AUTH: {
		// Проверяем имитовставку на заголовок
		// Расчет ИЗВ на заголовки
		if(!memcmp(block_HDR.respSPI, ikev2_sa->respSPI, 8)){
			// Проверка пакета AUTH для основного соединения
			result = ikev2_check_ike_sa_auth(data_in, len_data_in, ikev2_sa);
		}
		else {
			// Проверка пакета AUTH для дополнительных соединений
			result = mmt_check_ike_sa_a_auth(data_in, len_data_in, data_out, len_data_out);
		}
		break;
	}
	case INFORMATIONAL: {
		switch(block_HDR.nextPayload) {
			case ikev2_np_SK: {
				ikev2_block_SK block_SK;
				if(result = createBlockSKfromBuf(data_in+ikev2_SIZE_HDR, len_last, &block_SK))
					break;

				switch(block_SK.nextPayload) {
					case ikev2_np_notify : {
						if(result = ikev2_decriptSK(&block_SK, ikev2_sa))
							break;
						result = ikev2_processing_Notify(block_SK.encrData, block_SK.length-20);
						break;
					}
					case ikev2_np_delete : {
						if (*(unsigned long long *)ikev2_sa_pull[index_main_ikev2_sa].ikev2_sa->initSPI == *(unsigned long long *)block_HDR.initSPI
							&& *(unsigned long long *)ikev2_sa_pull[index_main_ikev2_sa].ikev2_sa->respSPI == *(unsigned long long *)block_HDR.respSPI) {
							result = IKE_CONTEXT_DEL;
						} else {
							result = IKE_OLD_CONTEXT_DEL;
						}
						break;
					}
					case ikev2_np_not : {
						if(!memcmp(block_HDR.respSPI, ikev2_sa->respSPI, 8)){
							// Для основного соединения
							result = IKE_KEPPALIVE_RECEIVED;
							break;
						}
						else {
							IKEv2_STRUCT_SA * ikev2_sa_a;
							if(result = get_ikev2_sa_a_by_spi(&ikev2_sa_a, block_HDR.initSPI)) {
								return result;
							}
							if(ikev2_sa_a->role == IKE_RESPONDER) {
								mmt_get_keepalive(ikev2_sa_a, data_out, len_data_out);
								result = IKE_KEPPALIVE_SEND;
							}
							else {
								result = IKE_KEPPALIVE_ADDITIONAL_RECEIVED;
							}
						}
					}
				}
				break;
			}
			default: {
				break;
			}
		}
		break;
	}
	default : {
		break;
    }

	}
	return result;
}

int ikev2_check_ike_sa_auth(unsigned char *dataIn, int lenDataIn, IKEv2_STRUCT_SA * ikev2_sa) {
	unsigned char izv[8];
	int result;
	int lenLast = lenDataIn;
	ikev2_block_HDR block_HDR;

	// Проверка блока HDR
	if ((lenLast - ikev2_SIZE_HDR) >= 0) {
		createBlockHDRfromBuf(dataIn, &block_HDR);
		if (result = check_block_hdr(&block_HDR, ikev2_sa)) {
			return result;
		}
	}
	lenLast = block_HDR.length;

	lenLast -= ikev2_SIZE_HDR;
#if defined(CRYPT_GOST28147)	
	GostStruct Cript;
	Cript.REGIM = MAKE_IMZ;
	Cript.Key = ikev2_sa->Kar;
	Cript.Din = dataIn;
	Cript.LenIMZ = LEN_IMZ_8;
	Cript.Dout = izv;
	Cript.LenBytes = 40;
	Cript.TR_STATE = 0;
	Cript.Tz = (unsigned char *) ikev2_sa->blockNote.Table;
	Gost28147(&Cript);
#elif defined(CRYPT_MAGMA)
	unsigned char imit_ctx[kImit89ContextLen];
	if(!cypher_magma_imit_init((unsigned char *)ikev2_sa->Kar, LEN_IMZ_8, imit_ctx))
		return IKE_ERR_MAGMA_IMIT_INIT;
	if(!cypher_imit(imit_ctx, dataIn, izv, 40))
		return IKE_ERR_MAGMA_IMIT;
	free_imit(imit_ctx);
#endif

	if(memcmp(izv, dataIn + 40, 8)) {
		return IKE_ERR_IMZ_HDR;
	}

	result = check_ike_sa_auth(dataIn + ikev2_SIZE_HDR, lenLast, ikev2_sa);
	return result;
}

int ikev2_decriptSK(ikev2_block_SK * block_SK, IKEv2_STRUCT_SA * ikev2_sa) {
	unsigned char imz[8];

#if defined(CRYPT_GOST28147)	
	// Расшифрование
	GostStruct Cript;
	Cript.REGIM		= GAMMIROVANIE_OS_REG;
	Cript.CRYPT		= DECRYPT;
	Cript.Key		= ikev2_sa->Ker;
	Cript.Sp		= block_SK->VI;
	Cript.Din		= block_SK->encrData;
	Cript.Dout		= block_SK->encrData;
	Cript.LenBytes	= block_SK->length - 28; //4 - заголовок, 8 - синхропосылка, 8 - изв, 8 - имитовставка
	Cript.TR_STATE	= TR_NO;
	Cript.Tz		= (unsigned char *)ikev2_sa->blockNote.Table;
	Gost28147(&Cript);

	// Расчет имитовставки
	Cript.REGIM		= MAKE_IMZ;
	Cript.Key		= ikev2_sa->Ker;
	Cript.LenIMZ	= LEN_IMZ_8;
	Cript.Din		= block_SK->encrData;
	Cript.Dout		= imz;
	Cript.LenBytes	= block_SK->length - 28;
	Cript.TR_STATE	= TR_NO;
	Cript.Tz		= (unsigned char *)ikev2_sa->blockNote.Table;
	Gost28147(&Cript);
#elif defined(CRYPT_MAGMA)
	unsigned char ctx[kCfb89ContextLen];
	if(!cypher_magma_cfb_init((unsigned char *)ikev2_sa->Ker, ctx, kBlockLen89, (unsigned char *)&block_SK->VI, 8))
		return IKE_ERR_MAGMA_CFB_INIT;

	int len_temp_buf = block_SK->length - 28;
	unsigned char * temp_buffer = (unsigned char * )malloc(len_temp_buf);
	if(!cypher_decr_cfb(ctx, block_SK->encrData, temp_buffer, len_temp_buf))
		return IKE_ERR_MAGMA_DECR;
	memcpy(block_SK->encrData, temp_buffer, len_temp_buf);
	free(temp_buffer);
	free_cfb(ctx);

	unsigned char imit_ctx[kImit89ContextLen];
	if(!cypher_magma_imit_init((unsigned char *)ikev2_sa->Ker, LEN_IMZ_8, imit_ctx))
		return IKE_ERR_MAGMA_IMIT_INIT;
	if(!cypher_imit(imit_ctx, block_SK->encrData, imz, block_SK->length - 28))
		return IKE_ERR_MAGMA_IMIT;
	free_imit(imit_ctx);
#endif
	if(memcmp(imz, block_SK->IMZ, 8)) {
		return IKE_ERR_IMZ_SK;
	}

	return IKE_OK;
}

int ikev2_processing_Notify(unsigned char * data, int lenData) {
	int result;
	ikev2_block_NOTIFY block_NOTIFY;

	if(result = createBlockNotifyfromBuf(data, lenData, &block_NOTIFY))
		return result;

	switch(block_NOTIFY.notifyMessageType) {
		case SET_NETWORK_SETTINGS: {
            result = mmt_save_tunnel(block_NOTIFY.Notify_Data,
									 block_NOTIFY.length - 8 - block_NOTIFY.sizeSPI);
			break;
		}
		default: {
			result = IKE_ERR_NOTIFY_MESSAGE_TYPE;
			break;
		}
	}

	return result;
}


int ikev2_check_time_sa() {
	time_t now_time = time(0);
	int is_create_new_ikev2_sa = 0;

	for(int i = 0; i < 2; i++) {
		if(ikev2_sa_pull[i].ikev2_sa != NULL) {
			if (now_time >= ikev2_sa_pull[i].time_end) {
				if ((i == 0 && ikev2_sa_pull[1].ikev2_sa->stage == IKE_STAGE_4)||
                        (i == 1 && ikev2_sa_pull[0].ikev2_sa->stage == IKE_STAGE_4)) {
                    pthread_mutex_lock(&ikev2_sa_mutex);
					pthread_mutex_lock(&ikev2_sa_mutex_processing_data);
					pthread_mutex_lock(&ikev2_sa_mutex_keepalive);
                    pthread_mutex_lock(&ikev2_sa_mutex_encapsul_data);

                    ikev2_clear(ikev2_sa_pull[i].ikev2_sa);
                    ikev2_sa_pull[i].ikev2_sa = NULL;
                    ikev2_sa_pull[i].time_end = 0;
                    ikev2_sa_pull[i].flag_checked = 0;
                    pthread_mutex_unlock(&ikev2_sa_mutex);
					pthread_mutex_unlock(&ikev2_sa_mutex_processing_data);
					pthread_mutex_unlock(&ikev2_sa_mutex_keepalive);
                    pthread_mutex_unlock(&ikev2_sa_mutex_encapsul_data);
				}
				continue;
			}

			if (now_time >= (ikev2_sa_pull[i].time_end - TIME_t) && ikev2_sa_pull[i].flag_checked == 0) {
				ikev2_sa_pull[i].flag_checked = 1;
				is_create_new_ikev2_sa = 1;
			}
		}
	}

	return is_create_new_ikev2_sa;
}

/**
 * Функция очистки контекста SA
 * @param ikev2_sa
 */
void ikev2_clear(IKEv2_STRUCT_SA * ikev2_sa) {
	if(ikev2_sa != NULL) {
		if (ikev2_sa->nonceR != NULL) {
			free(ikev2_sa->nonceR);
			ikev2_sa->nonceR = NULL;
		}
		if (ikev2_sa->nonceI != NULL) {
			free(ikev2_sa->nonceI);
			ikev2_sa->nonceI = NULL;
		}

		if (ikev2_sa->TSi != NULL) {
			free(ikev2_sa->TSi);
			ikev2_sa->TSi = NULL;
		}
		if (ikev2_sa->TSr != NULL) {
			free(ikev2_sa->TSr);
			ikev2_sa->TSr = NULL;
		}
		if (ikev2_sa->proposals != NULL) {
			if (ikev2_sa->proposals->transforms != NULL) {
				free(ikev2_sa->proposals->transforms);
				ikev2_sa->proposals->transforms = NULL;
			}
			free(ikev2_sa->proposals);
			ikev2_sa->proposals = NULL;
		}

        memset((unsigned char *)ikev2_sa, 0, sizeof(IKEv2_STRUCT_SA));
		free(ikev2_sa);
		ikev2_sa = NULL;

        //delete_all_ikev2_sa_a();
        //delete_all_wait_packets();
        //delete_all_tunnels();
	}
}

void ikev2_close() {
	for (int i = 0; i < 2; i++) {
		ikev2_clear(ikev2_sa_pull[i].ikev2_sa);
		ikev2_sa_pull[i].ikev2_sa = NULL;
	}
    index_main_ikev2_sa = -1;
}