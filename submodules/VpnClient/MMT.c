#include <stdlib.h>
#include <string.h>
#include <updsch_manager.h>

#include "MMT.h"
#include "IKEv2.h"
#include "ESP.h"
#include "F.h"
#include "crc32.h"
#include "time.h"
#include "nonce.h"
#if defined(CRYPT_GOST28147)
    #include "Gost28147.h"
#elif defined(CRYPT_MAGMA)
    #include "cypher.h"
#endif
mmt_WAIT_PACKET_CHAIN       *wait_packet_buf = NULL;
IKEV2_SA_ADDITINAL_CHAIN    *ikev2_sa_additional_buf = NULL;
mmt_TUNNEL_CHAIN            *ikev2_tunnels = NULL;

/* ++ Локальные функции ++ */

/*
 * Функция помещения ожидающего IP-пакета в глобальный контейнер
 */
static void push_wp(mmt_WAIT_PACKET *data, mmt_WAIT_PACKET_CHAIN **head) {
    mmt_WAIT_PACKET_CHAIN *tmp = (mmt_WAIT_PACKET_CHAIN*) malloc(sizeof(mmt_WAIT_PACKET_CHAIN));
    tmp->value = data;
    tmp->next = (*head);
    (*head) = tmp;
}

/*
 * Функция изъятия ожидающего IP-пакета из глобального контейнера
 */
static mmt_WAIT_PACKET * pop_wp(mmt_WAIT_PACKET_CHAIN **head) {
    mmt_WAIT_PACKET_CHAIN* prev = NULL;
    mmt_WAIT_PACKET * val;
    if (head == NULL) {
        return NULL; ///!!!!!
    }
    prev = (*head);
    val = prev->value;
    (*head) = (*head)->next;
    free(prev);
    return val;
}

/*
 * Функция помещения IKE контекста в глобальный контейнер
 */
static void push_sa(IKEv2_STRUCT_SA *data, IKEV2_SA_ADDITINAL_CHAIN **head) {
    IKEV2_SA_ADDITINAL_CHAIN *tmp = (IKEV2_SA_ADDITINAL_CHAIN*) malloc(sizeof(IKEV2_SA_ADDITINAL_CHAIN));
    tmp->value = data;
    tmp->last_time_response = tmp->last_time_keepalive = time(0);
    tmp->count_keepalive = 0;
    tmp->next = (*head);
    (*head) = tmp;
}

/*
 * Функция изъятия IKE контекста из глобального контейнера
 */
static IKEv2_STRUCT_SA * pop_sa(IKEV2_SA_ADDITINAL_CHAIN **head) {
    IKEV2_SA_ADDITINAL_CHAIN* prev = NULL;
    IKEv2_STRUCT_SA * val;
    prev = (*head);
    val = prev->value;
    (*head) = (*head)->next;
    free(prev);
    return val;
}


/*
 * Функция сохранения ip-пакета
 * Вход:
 *  net_num - сетевой номер сети назначения
 *  data_in - ip-пакет
 *  len_data_in - размер ip-пакета
 */
static void save_packet(unsigned short net_num, unsigned char *data_in, unsigned int len_data_in) {
    mmt_WAIT_PACKET * wait_paket = (mmt_WAIT_PACKET *)malloc(sizeof(mmt_WAIT_PACKET));
    wait_paket->net_num = net_num;
    wait_paket->len_data = len_data_in;
    wait_paket->data = (unsigned char *)malloc(len_data_in);
    memcpy(wait_paket->data, data_in, len_data_in);
    push_wp(wait_paket, &wait_packet_buf);
}

/*
 * Функция формирования пакета IKE_SA_INIT
 * Вход:
 *  ikev2_sa_a - IKE контекст
 * Выход:
 *  data_out - пакет IKE_SA_INIT
 *  len_data_out - размер data_out
 */

static void get_ike_sa_a_init(IKEv2_STRUCT_SA *ikev2_sa_a, unsigned char **data_out,
                              unsigned int *len_data_out) {
    unsigned char * buffer;

    //Если контекст еще не создавался
    if(ikev2_sa_a == NULL) {
        *len_data_out = 0;
        *data_out = NULL;
        return;
    }

    //Подсчет длины всего сообщения IKE_SA_INIT
    *len_data_out = ikev2_SIZE_HDR +
                  ikev2_SIZE_SA_H +
                  ikev2_SIZE_KE_H + (ikev2_size_Key_data) +
                  ikev2_SIZE_NONCE_H +
                  24 + //2 * 12 (notify)
                  ikev2_SIZE_VID_H;

    buffer = (unsigned char *)malloc(*len_data_out + ikev2_SIZE_START_ZERO);
    memset(buffer, 0, *len_data_out+ikev2_SIZE_START_ZERO);
    buffer += ikev2_SIZE_START_ZERO;
    //HDR
    memcpy(buffer, ikev2_sa_a->initSPI, 8);                                 // Init SPi
    memcpy(buffer+8, ikev2_sa_a->respSPI, 8);   			                // Resp SPI
    *(unsigned char *)(buffer + 16)		= ikev2_np_sa;			            // Next Payload
    *(unsigned char *)(buffer + 17)		= 0x20;						        // Ver
    *(unsigned char *)(buffer + 18)		= IKE_SA_INIT;				        // Exchange Type
    *(unsigned char *)(buffer + 19)		= ikev2_sa_a->role ? 0x08 : 0x20;   // Flags
    *(unsigned int *)(buffer + 20)		= 0;		                        // Message ID
    *(unsigned int *)(buffer + 24)		= reverse32(*len_data_out);

    //SAi
    *(unsigned char *)(buffer + 28)		= ikev2_np_ke;										// Next Payload
    *(unsigned char *)(buffer + 29)		= 0;
    *(unsigned short *)(buffer + 30)	= reverse16(ikev2_SIZE_SA_H);// reverse16((ikev2_SIZE_TRANSFORM_H * ikev2_sa->proposals->num_transf) * ikev2_sa->num_prop + ikev2_SIZE_PROPOSAL_H + ikev2_SIZE_SA_H);

    //Proposals
    *(unsigned char *)(buffer + 32)		= 0;												// last
    *(unsigned char *)(buffer + 33)		= 0;												//RESERVED
    *(unsigned short *)(buffer + 34)	= reverse16((ikev2_SIZE_TRANSFORM_H * ikev2_sa_a->proposals->num_transf) * ikev2_sa_a->num_prop + ikev2_SIZE_PROPOSAL_H);  //len
    *(unsigned char *)(buffer + 36)		= 1;												//Переписать формирование массива !!!
    *(unsigned char *)(buffer + 37)		= 1;												//Protocol ID
    *(unsigned char *)(buffer + 38)		= 0;
    *(unsigned char *)(buffer + 39)		= ikev2_sa_a->proposals->num_transf;

    //Transforms
    *(unsigned char *)(buffer + 40)		= 3;												//more
    *(unsigned char *)(buffer + 41)		= 0;												//RESERVED
    *(unsigned short *)(buffer + 42)	= reverse16(ikev2_SIZE_TRANSFORM_H);				//len
    *(unsigned char *)(buffer + 44)		= ikev2_sa_a->proposals->transforms[0].type;		//Transform Type
    *(unsigned char *)(buffer + 45)		= 0;												//RESERVED
    *(unsigned short *)(buffer + 46)	= reverse16(ikev2_sa_a->proposals->transforms[0].id);//Transform ID

    *(unsigned char *)(buffer + 48)		= 0;												//last
    *(unsigned char *)(buffer + 49)		= 0;												//RESERVED
    *(unsigned short *)(buffer + 50)	= reverse16(ikev2_SIZE_TRANSFORM_H);				//len
    *(unsigned char *)(buffer + 52)		= ikev2_sa_a->proposals->transforms[1].type;			//Transform Type
    *(unsigned char *)(buffer + 53)		= 0;												//RESERVED
    *(unsigned short *)(buffer + 54)	= reverse16(ikev2_sa_a->proposals->transforms[1].id); //Transform ID

    //KEi KEr
    *(unsigned char *)(buffer + 56)		= ikev2_np_nonce;									//Next Payload;
    *(unsigned char *)(buffer + 57)		= 0;												//RESERVED
    *(unsigned short *)(buffer + 58)	= reverse16(ikev2_SIZE_KE_H + ikev2_size_Key_data);						//len
    *(unsigned short *)(buffer + 60)	= reverse16(1024);									//DH Group
    *(unsigned short *)(buffer + 62)	= 0;												//RESERVED
    memcpy((buffer + 64), ikev2_sa_a->blockNote.name, 8);
    memcpy((buffer + 72), ikev2_sa_a->blockNote.Nserial, 8);
    *(unsigned short *)(buffer + 80) = ikev2_sa_a->blockNote.NKompl;
    *(unsigned short *)(buffer + 82) = ikev2_sa_a->blockNote.numOfKompl;

    int sdvig = 64 + ikev2_size_Key_data;

    //Ni Nr
    *(unsigned char *)(buffer + sdvig)			= ikev2_np_notify;				// Next Payload;
    *(unsigned char *)(buffer + sdvig + 1)		= 0;							//RESERVED
    *(unsigned short *)(buffer + sdvig + 2)		= reverse16(ikev2_SIZE_NONCE_H);//len

    if(ikev2_sa_a->role == IKE_INITIATOR)
        memcpy(buffer + (sdvig + 4), ikev2_sa_a->nonceI, 8);
    else
        memcpy(buffer + (sdvig + 4), ikev2_sa_a->nonceR, 8);

    //N1
    *(unsigned char *)(buffer + sdvig + 12)		= ikev2_np_notify;
    *(unsigned char *)(buffer + sdvig + 13)		= 0;
    *(unsigned short *)(buffer + sdvig + 14)	= reverse16(12);		//len
    *(unsigned char *)(buffer + sdvig + 16)		= 1;
    *(unsigned char *)(buffer + sdvig + 17)		= 0;
    *(unsigned short *)(buffer + sdvig + 18)	= reverse16(NAT_DETECTION_SOURCE_IP);

    //Расчет CRC32
    unsigned char * data = (unsigned char *) malloc(24);
    memcpy(data, ikev2_sa_a->initSPI, 8);
    memcpy(data + 8, ikev2_sa_a->respSPI, 8);
    memcpy(data + 16, (unsigned char *) &ikev2_sa_a->lanIpAdr, 4);
    memcpy(data + 20, (unsigned char *) &ikev2_sa_a->lanPort , 2);
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
    memcpy(data + 16, (unsigned char *) &ikev2_sa_a->wanIpAdr, 4);
    memcpy(data + 20, (unsigned char *) &ikev2_sa_a->wanPort , 2);
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

/*
 * Функция формирования пакета IKE_SA_AUTH
 * Вход:
 *  ikev2_sa_a - IKE контекст
 * Выход:
 *  data_out - пакет IKE_SA_AUTH
 *  len_data_out - размер data_out
 */
static void get_ike_sa_a_auth(IKEv2_STRUCT_SA *ikev2_sa_a, unsigned char **dataOut,
                       unsigned int *lenDataOut) {
    unsigned int sizeBlockCripto, lenCriptoData;
    unsigned int lenPadLength;
    unsigned char lenPad;
    unsigned char izv[8];
    unsigned int A[4];
    unsigned char temp[32];
    unsigned char * buffer;

    if(ikev2_sa_a == NULL) {
        if(ikev2_sa_a->role&& ikev2_sa_a->stage != IKE_STAGE_2)
            return;
        else if(!ikev2_sa_a->role && ikev2_sa_a->stage != IKE_STAGE_4)
            return;
    }

    //Подсчет длины всего сообщения IKE_AUTH
    lenCriptoData = ikev2_SIZE_ID_H +
                    ikev2_SIZE_AUTH_H +
                    (ikev2_SIZE_TRANSFORM_H * ikev2_sa_a->proposals->num_transf) * ikev2_sa_a->num_prop +
                    ikev2_SIZE_PROPOSAL_H + 8 + 48;

    sizeBlockCripto = 8;
    lenPadLength = 1;
    lenPad = (sizeBlockCripto -  (lenCriptoData + lenPadLength) % sizeBlockCripto);

    *lenDataOut = lenPad +
                  lenCriptoData +
                  ikev2_SIZE_SK_H +
                  ikev2_SIZE_HDR +
                  lenPadLength;

    buffer = (unsigned char *)malloc(*lenDataOut+4);
    memset(buffer, 0, 4);
    buffer += 4;
    //HDR
    memcpy(buffer, ikev2_sa_a->initSPI, 8);                         // Init SPi
    memcpy(buffer+8, ikev2_sa_a->respSPI, 8);   			        // Resp SPI
    *(unsigned char *)(buffer + 16)		= ikev2_np_SK;			    // Next Payload
    *(unsigned char *)(buffer + 17)		= 0x20;						// Ver
    *(unsigned char *)(buffer + 18)		= IKE_AUTH;					// Exchange Type
    *(unsigned char *)(buffer + 19)		= ikev2_sa_a->role ? 0x08 : 0x20;	  // Flags
    ikev2_sa_a->outMessageID = 1;
    *(unsigned int *)(buffer + 20)		= reverse32(ikev2_sa_a->outMessageID);// Message ID
    *(unsigned int *)(buffer + 24)		= reverse32(*lenDataOut);

    //SK
    *(unsigned char *)(buffer + 28)		= ikev2_sa_a->role ? ikev2_np_idi : ikev2_np_idr;			// Next Payload
    *(unsigned char *)(buffer + 29)		= 0;
    *(unsigned short *)(buffer + 30)	= reverse16(ikev2_SIZE_SK_H + lenCriptoData + lenPad + lenPadLength);

    //*(unsigned int *)(buffer + 32)		= random();				//Initialization Vector
    //*(unsigned int *)(buffer + 36)		= random();				//Initialization Vector
    memcpy(buffer + 32, get_random(ikev2_sa_a->SecureIdentifyInf), 8);
    // Расчет ИЗВ на заголовки
#if defined(CRYPT_GOST28147)	
    GostStruct Cript;
    Cript.REGIM		= MAKE_IMZ;
    Cript.Key       = ikev2_sa_a->role ? ikev2_sa_a->Kai : ikev2_sa_a->Kar;
    Cript.Din		= buffer;
    Cript.LenIMZ	= LEN_IMZ_8;
    Cript.Dout		= izv;
    Cript.LenBytes	= 40;
    Cript.TR_STATE	= 0;
    Cript.Tz		= (unsigned char *)ikev2_sa_a->blockNote.Table;
    Gost28147(&Cript);
#elif defined(CRYPT_MAGMA)
    unsigned char imit_ctx[kImit89ContextLen];
    if(!cypher_magma_imit_init((unsigned char *)ikev2_sa_a->role ? ikev2_sa_a->Kai : ikev2_sa_a->Kar, LEN_IMZ_8, imit_ctx))
        return;
    if(!cypher_imit(imit_ctx, buffer, izv, 40))
        return;
    free_imit(imit_ctx);
#endif
    memcpy((buffer + 40), izv, 8);

    /* Данные для шифрования */
    //ID
    *(unsigned char *)(buffer  + 48)		= ikev2_np_auth;			    // Next Payload
    *(unsigned char *)(buffer  + 49)		= 0;
    *(unsigned short *)(buffer + 50)		= reverse16(ikev2_SIZE_ID_H);	//Len
    *(unsigned char *)(buffer  + 52)		= 201;						    //ID Type
    *(unsigned short *)(buffer + 53)		= 0;
    *(unsigned char *)(buffer  + 55)		= 0;
    memcpy((buffer + 56), ikev2_sa_a->blockNote.name, 8);
    memcpy((buffer + 64), ikev2_sa_a->blockNote.Nserial, 8);
    memcpy((buffer + 72), (unsigned char *)&ikev2_sa_a->blockNote.numOfKompl, 2);
    memcpy((buffer + 74), (unsigned char *)&ikev2_sa_a->blockNote.NKompl, 2);

    // Блок AUTH
    *(unsigned char *)(buffer + 76)		= ikev2_np_sa;			        // Next Payload
    *(unsigned char *)(buffer + 77)		= 0;
    *(unsigned short *)(buffer + 78)	= reverse16(ikev2_SIZE_AUTH_H);	//Len
    *(unsigned char *)(buffer + 80)		= 201;					        //Auth Method
    *(unsigned short *)(buffer + 81)	= 0;
    *(unsigned char *)(buffer + 83)		= 0;

    //Генерация ESP_SPI
    if(ikev2_sa_a->role)
        ikev2_sa_a->espInitSPI = (*(unsigned int *)(ikev2_sa_a->initSPI + 4) & 0xFFFF) | ((*(unsigned int *)(ikev2_sa_a->respSPI+4)& 0xFFFF0000));
    else
        ikev2_sa_a->espRespSPI = (*(unsigned int *)(ikev2_sa_a->respSPI + 4) & 0xFFFF) | ((*(unsigned int *)(ikev2_sa_a->initSPI+4)& 0xFFFF0000));
                //Расчет AUTHi
    memset(temp, 0 , 32);
    memcpy(temp  , ikev2_sa_a->initSPI, 8);
    memcpy(temp+8, ikev2_sa_a->respSPI, 8);

    if(ikev2_sa_a->role) {
        memcpy(temp + 16, (unsigned char *) &ikev2_sa_a->espInitSPI, 4);
        temp[20] = 1;
    }
    else {
        memcpy(temp + 16, (unsigned char *) &ikev2_sa_a->espRespSPI, 4);
        temp[20] = 5;
    }
	
#if defined(CRYPT_GOST28147)	
    Cript.REGIM		= MAKE_IMZ;
    Cript.Key       = ikev2_sa_a->role ? ikev2_sa_a->Kai : ikev2_sa_a->Kar;
    Cript.LenIMZ	= LEN_IMZ_4;
    Cript.Din		= temp;
    Cript.Dout		= (unsigned char *)&A[0];
    Cript.LenBytes	= 24;
    Cript.TR_STATE	= 0;
    Cript.Tz		= (unsigned char *)ikev2_sa_a->blockNote.Table;
    Gost28147(&Cript);
#elif defined(CRYPT_MAGMA)
    if(!cypher_magma_imit_init((unsigned char *)ikev2_sa_a->role ? ikev2_sa_a->Kai : ikev2_sa_a->Kar, LEN_IMZ_4, imit_ctx))
        return;
    if(!cypher_imit(imit_ctx, temp, (unsigned char *)&A[0], 24))
        return;
    free_imit(imit_ctx);
#endif
    memcpy(temp+4, ikev2_sa_a->initSPI, 8);
    memcpy(temp+12, ikev2_sa_a->respSPI, 8);
    if(ikev2_sa_a->role)
        memcpy(temp+20, (unsigned char *)&ikev2_sa_a->espInitSPI, 4);
    else
        memcpy(temp+20, (unsigned char *)&ikev2_sa_a->espRespSPI, 4);

    for(int i = 1; i < 4; i++) {
        memcpy(temp  , (unsigned char *)&A[i-1], 4);
        temp[24] = ikev2_sa_a->role ? i+1 : i+5;
#if defined(CRYPT_GOST28147)
        Cript.Din		= temp;
        Cript.Dout		= (unsigned char *)&A[i];
        Cript.LenBytes	= 32;
        Cript.TR_STATE	= 0;
        Cript.Tz		= (unsigned char *)ikev2_sa_a->blockNote.Table;
        Gost28147(&Cript);
#elif defined(CRYPT_MAGMA)
        if(!cypher_magma_imit_init((unsigned char *)ikev2_sa_a->role ? ikev2_sa_a->Kai : ikev2_sa_a->Kar, LEN_IMZ_4, imit_ctx))
            return;
        if(!cypher_imit(imit_ctx, temp, (unsigned char *)&A[i], 32))
            return;
        free_imit(imit_ctx);
#endif
    }

    memcpy((buffer + 84),A,16);

    // Блок SA

    *(unsigned char *)(buffer + 100)		= ikev2_np_TSi;										// Next Payload
    *(unsigned char *)(buffer + 101)		= 0;
    *(unsigned short *)(buffer + 102)	    = reverse16((ikev2_SIZE_TRANSFORM_H * ikev2_sa_a->proposals->num_transf) * ikev2_sa_a->num_prop + ikev2_SIZE_PROPOSAL_H + 4 + 4);

    //Proposals
    *(unsigned char *)(buffer + 104)		= 0;												// last
    *(unsigned char *)(buffer + 105)		= 0;												//RESERVED
    *(unsigned short *)(buffer + 106)	    = reverse16((ikev2_SIZE_TRANSFORM_H * ikev2_sa_a->proposals->num_transf) * ikev2_sa_a->num_prop + ikev2_SIZE_PROPOSAL_H + 4);  //len
    *(unsigned char *)(buffer + 108)		= 1;												//Переписать формирование массива !!!
    *(unsigned char *)(buffer + 109)		= 3;												//Protocol ID
    *(unsigned char *)(buffer + 110)		= 4;												//SPI size
    *(unsigned char *)(buffer + 111)		= ikev2_sa_a->proposals->num_transf;
    *(unsigned int *)(buffer + 112)		    = ikev2_sa_a->role ? ikev2_sa_a->espInitSPI : ikev2_sa_a->espRespSPI;
    //Transforms
    *(unsigned char *)(buffer + 116)		= 3;												//more
    *(unsigned char *)(buffer + 117)		= 0;												//RESERVED
    *(unsigned short *)(buffer + 118)	    = reverse16(ikev2_SIZE_TRANSFORM_H);				//len
    *(unsigned char *)(buffer + 120)		= ikev2_sa_a->proposals->transforms[0].type;		//Transform Type
    *(unsigned char *)(buffer + 121)		= 0;												//RESERVED
    *(unsigned short *)(buffer + 122)	    = reverse16(ikev2_sa_a->proposals->transforms[0].id);	//Transform ID

    *(unsigned char *)(buffer + 124)		= 0;												//last
    *(unsigned char *)(buffer + 125)		= 0;												//RESERVED
    *(unsigned short *)(buffer + 126)	    = reverse16(ikev2_SIZE_TRANSFORM_H);				//len
    *(unsigned char *)(buffer + 128)		= ikev2_sa_a->proposals->transforms[1].type;		//Transform Type
    *(unsigned char *)(buffer + 129)		= 0;												//RESERVED
    *(unsigned short *)(buffer + 130)		= reverse16(ikev2_sa_a->proposals->transforms[1].id); //Transform ID

    // Возможно можно убрать
    //Блок TSi
    *(unsigned char *)(buffer + 132)		= ikev2_np_TSr;			// Next Payload
    *(unsigned char *)(buffer + 133)		= 0;
    *(unsigned short *)(buffer + 134)	    = reverse16(24);		// Len
    *(unsigned char *)(buffer + 136)		= 1;					// Number of TSs
    *(unsigned short *)(buffer + 137)	    = 0;
    *(unsigned char *)(buffer + 139)		= 0;

    // Trafic Selector
    *(unsigned char *)(buffer + 140)		= 7;					// TS type  (TS_IPV4_ADDR_RANGE)
    *(unsigned char *)(buffer + 141)		= 0;					// IP Protocol ID (0 - ID протокола не важен)
    *(unsigned short *)(buffer + 142)	    = reverse16(16);		// Selector Len
    *(unsigned short *)(buffer + 144)	    = 0;					// Start port
    *(unsigned short *)(buffer + 146)	    = reverse16(65535);		// End port
    *(unsigned int *)(buffer + 148)		    = 0;					// Starting address
    *(unsigned int *)(buffer + 152)		    = 0xFFFFFFFF;			// Ending address

    //Блок TSr
    *(unsigned char *)(buffer + 156)		= ikev2_np_not;			// Next Payload
    *(unsigned char *)(buffer + 157)		= 0;
    *(unsigned short *)(buffer + 158)	    = reverse16(24);		// Len
    *(unsigned char *)(buffer + 160)		= 1;					// Number of TSs
    *(unsigned short *)(buffer + 161)	    = 0;
    *(unsigned char *)(buffer + 163)		= 0;

    // Trafic Selector
    *(unsigned char *)(buffer + 164)		= 7;					// TS type  (TS_IPV4_ADDR_RANGE)
    *(unsigned char *)(buffer + 165)		= 0;					// IP Protocol ID (0 - ID протокола не важен)
    *(unsigned short *)(buffer + 166)	    = reverse16(16);		// Selector Len
    *(unsigned short *)(buffer + 168)	    = 0;					// Start port
    *(unsigned short *)(buffer + 170)	    = reverse16(65535);		// End port
    *(unsigned int *)(buffer + 172)		    = 0;					// Starting address
    *(unsigned int *)(buffer + 176)		    = 0xFFFFFFFF;			// Ending address

    for(int i = 1; i <= lenPad; i++) {
        buffer[*lenDataOut - 9 - (lenPad + 1 - i)] = i;
    }

    *(buffer + (*lenDataOut - 9)) = lenPad;

#if defined(CRYPT_GOST28147)	
    // Расчет имитовставки
    Cript.REGIM		= MAKE_IMZ;
    Cript.Key		= ikev2_sa_a->role ? ikev2_sa_a->Kei : ikev2_sa_a->Ker;
    Cript.LenIMZ	= LEN_IMZ_8;
    Cript.Din		= buffer + 48;
    Cript.Dout		= buffer + (*lenDataOut - 8);
    Cript.LenBytes	= lenPad + lenCriptoData + lenPadLength;
    Cript.TR_STATE	= TR_NO;
    Cript.Tz		= (unsigned char *)ikev2_sa_a->blockNote.Table;
    Gost28147(&Cript);

    // Шифрование
    Cript.REGIM	= GAMMIROVANIE_OS_REG;
    Cript.CRYPT	= ENCRYPT;
    Cript.Key   = ikev2_sa_a->role ? ikev2_sa_a->Kei : ikev2_sa_a->Ker;
    Cript.Sp	= (unsigned int *)(buffer + 32);
    Cript.Din	= buffer + 48;
    Cript.Dout	= buffer + 48;
    Cript.LenBytes = lenPad + lenCriptoData + lenPadLength;
    Cript.TR_STATE = TR_NO;
    Cript.Tz	= (unsigned char *)ikev2_sa_a->blockNote.Table;
    Gost28147(&Cript);
#elif defined(CRYPT_MAGMA)
    if(!cypher_magma_imit_init((unsigned char *)ikev2_sa_a->role ? ikev2_sa_a->Kei : ikev2_sa_a->Ker, LEN_IMZ_8, imit_ctx))
        return;
    if(!cypher_imit(imit_ctx,buffer + 48, buffer + (*lenDataOut - 8), lenPad + lenCriptoData + lenPadLength))
        return;
    free_imit(imit_ctx);

    unsigned char ctx[kCfb89ContextLen];
    if(!cypher_magma_cfb_init((unsigned char *)ikev2_sa_a->role ? ikev2_sa_a->Kei : ikev2_sa_a->Ker, ctx, kBlockLen89, buffer + 32, 8))
        return;

    int len_temp_buf = lenPad + lenCriptoData + lenPadLength;
    unsigned char * temp_buffer = (unsigned char * )malloc(len_temp_buf);
    if(!cypher_encr_cfb(ctx, buffer + 48, temp_buffer, len_temp_buf))
        return;
    free_cfb(ctx);
    memcpy(buffer + 48, temp_buffer, len_temp_buf);
    free(temp_buffer);
#endif

    if(ikev2_sa_a->role == IKE_INITIATOR)
        ikev2_sa_a->stage = IKE_STAGE_3;
    *lenDataOut += 4;
    buffer -= 4;
    *dataOut = buffer;
}


/*
 *
 *
 */
static void delete_ikev2_sa_a(IKEv2_STRUCT_SA *ikev2_sa_a) {
    if (ikev2_sa_a->nonceR != NULL) {
        free(ikev2_sa_a->nonceR);
        ikev2_sa_a->nonceR = NULL;
    }
    if (ikev2_sa_a->nonceI != NULL) {
        free(ikev2_sa_a->nonceI);
        ikev2_sa_a->nonceI = NULL;
    }

    if (ikev2_sa_a->TSi != NULL) {
        free(ikev2_sa_a->TSi);
        ikev2_sa_a->TSi = NULL;
    }
    if (ikev2_sa_a->TSr != NULL) {
        free(ikev2_sa_a->TSr);
        ikev2_sa_a->TSr = NULL;
    }

    if (ikev2_sa_a->proposals != NULL) {
        if (ikev2_sa_a->proposals->transforms != NULL) {
            free(ikev2_sa_a->proposals->transforms);
            ikev2_sa_a->proposals->transforms = NULL;
        }
        free(ikev2_sa_a->proposals);
        ikev2_sa_a->proposals = NULL;
    }

    free(ikev2_sa_a);
    ikev2_sa_a = NULL;
}

/*
 * Функция по сетевому номеру сервера находит ожидающий IP-пакет.
 * Вход:
 *  net_num - сетевой номер сервера
 *  head - ссылка на глобальный контейнет ожидающих IP-пакетов
 * Выход
 *  ожидающий IP-пакет
 */
static mmt_WAIT_PACKET * get_wait_packet(mmt_WAIT_PACKET_CHAIN **head, unsigned short net_num) {
    mmt_WAIT_PACKET_CHAIN * tmp = *(head);
    mmt_WAIT_PACKET_CHAIN * pred;
    mmt_WAIT_PACKET * value;
    if(tmp->value->net_num == net_num) {
        return pop_wp(head);
    }
    pred = tmp;
    tmp = tmp->next;
    while(tmp) {
        if(tmp->value->net_num == net_num) {
            pred->next = tmp->next;
            value = tmp->value;
            free(tmp);
            return value;
        }
        pred = tmp;
        tmp = tmp->next;
    }

    return NULL;
}

/*
 *  Функция удаления IKE контекста из глобального контейнера
 *  Вход:
 *      head - глобальный контейнер дополнительных IKE контекстов
 *      item - удаляемый элемент
 */
static void delete_item(IKEv2_STRUCT_SA *item, IKEV2_SA_ADDITINAL_CHAIN **head) {
    IKEV2_SA_ADDITINAL_CHAIN * tmp = *(head);
    IKEV2_SA_ADDITINAL_CHAIN * pred;

    if(tmp->value == item) {
        pop_sa(head);
        return;
    }
    pred = tmp;
    tmp = tmp->next;
    while(tmp) {
        if(tmp == item) {
            if(tmp->value->role == IKE_INITIATOR)
                while(get_wait_packet(&wait_packet_buf, tmp->value->serverNetNumber)) {}
            delete_ikev2_sa_a(tmp->value);
            pred->next = tmp->next;
            free(tmp);
            tmp = NULL;
            item = pred;
        }
        pred = tmp;
        tmp = tmp->next;
    }
}

/*
 * Функция добавления тунеля в список
 */
static void push_tunnel(ikev2_TUNNEL *tunnel, mmt_TUNNEL_CHAIN **head) {
    mmt_TUNNEL_CHAIN *tmp = (mmt_TUNNEL_CHAIN *) malloc(sizeof(mmt_TUNNEL_CHAIN));
    tmp->tunnel = tunnel;
    tmp->next = (*head);
    (*head) = tmp;
}

/*
 * Функция извлечения тунеля из списока
 */
static ikev2_TUNNEL * pop_tunnel(mmt_TUNNEL_CHAIN **head) {
    mmt_TUNNEL_CHAIN* prev = NULL;
    ikev2_TUNNEL * tunnel;
    prev = (*head);
    tunnel = prev->tunnel;
    (*head) = (*head)->next;
    free(prev);
    return tunnel;
}

/*
 * Функция поиска тунеля в списке
 */
static ikev2_TUNNEL * search_tunnel(ikev2_TUNNEL *tunnel, mmt_TUNNEL_CHAIN *head) {
    mmt_TUNNEL_CHAIN * temp = head;
    ikev2_TUNNEL * rearched_tunnel = NULL;

    while(temp) {
        if(!memcmp((unsigned char *)(temp->tunnel), (unsigned char *)tunnel, sizeof(ikev2_TUNNEL))) {
            rearched_tunnel = tunnel;
            break;
        }
        temp = temp->next;
    }

    return rearched_tunnel;
}

/*
 * Функция удаления всех туннелей
 */
void delete_all_tunnels() {
    ikev2_TUNNEL * tunnel;
    if(wait_packet_buf == NULL)
        return;
    while(wait_packet_buf) {
        tunnel = pop_tunnel(&ikev2_tunnels);
        free(tunnel);
    }
}




/* -- Локальные функции -- */


/*
 *  Функция сохранения данных, содержащих туннели центрального сервера.
 *  Тунели для сети текущего устройства не сохраняеются
 *  Вход:
 *      data - данные;
 *      len_data - размер данных.
 *  Выход: результат выполнения.
 */
unsigned int mmt_save_tunnel(unsigned char *data, int len_data) {
    int nuf_of_block;
    unsigned char * temp_data;
    IKEv2_STRUCT_SA * ikev2_sa = ikev2_sa_pull[index_main_ikev2_sa].ikev2_sa;

    if(len_data < sizeof(ikev2_TUNNEL))
        return IKE_ERR_LEN;

    temp_data = data;
    nuf_of_block = len_data / SIZE_TUNNEL_STRUCT;

    // Копирование настроек
    for(int i = 0; i < nuf_of_block; i++) {
        if(((ikev2_TUNNEL*)temp_data)->net_num != ikev2_sa->netNumber) {
            if(!search_tunnel((ikev2_TUNNEL*)(temp_data), ikev2_tunnels)) {
                push_tunnel((ikev2_TUNNEL*)(temp_data), &ikev2_tunnels);
            }
        }
        temp_data += SIZE_TUNNEL_STRUCT;
    }

    return IKE_OK;
}

/*
 * Функция обработки пакета, не предназначеного для сети центрального шифратора
 * Принимает пакет и проверяет его адрес назначения, если по адресу в сетевых
 * настройках найден сетевой номер щифратора, формируется IKE_SA для данного шифратора
 * Вход:
 *  data_in - ip-пакет
 *  len_data_in - размер ip-пакета
 * Выход:
 *   результат обработки
 *   data_out - если data_in это первый ip-пакет в туннель для которого еще не создано соединение, то пакет IKE_ISA_INIT,
 *              иначе это ESP-пакет с упакованным data_in
 *   len_data_out - размер data_out
 */
unsigned int proc_pack_for_another_network(unsigned char *data_in, int len_data_in,
                                           unsigned char **data_out, int *len_data_out) {
    unsigned int result;
    unsigned short net_num = 0;
    IKEv2_STRUCT_SA * ikev2_sa_a = NULL;

    *len_data_out = 0;
    *data_out = NULL;
    // 1. Проверка основного контекста безопаности
    IKEv2_STRUCT_SA * ikev2_sa = ikev2_sa_pull[index_main_ikev2_sa].ikev2_sa;
    if((result = check_ikesa_stage(ikev2_sa))) return result;
    // 2. Поиск в сетевых настройках сетевой номер шифратора сети назначения
    if((result = search_netnum_by_ipnetwork(reverse32(*(unsigned int *)(data_in + 16)), &net_num))) {
        return result;
    }
    // 3. Поиск по сетевому номеру уже созданного соединения или создание нового
    switch(get_ikev2_sa_a_by_nn(net_num, &ikev2_sa_a)) {
        case IKEv2_NEW : {
            // 4. Создано новое IKE соединение, сохранение пакета для последующей передачи
            save_packet(net_num, data_in, len_data_in);

            // 5. Инициализация дополнительного IKE соединения
            ikev2_sa_a_init(ikev2_sa_a, IKE_INITIATOR, ikev2_sa->netNumber, net_num);

            // 6. Формирование пакета IKE_SA_INIT
            get_ike_sa_a_init(ikev2_sa_a, data_out, len_data_out);
            ikev2_sa_a->stage = IKE_STAGE_1;

            result = IKE_OK;
            break;
        }
        case IKEv2_OLD: {
            // 4. Соединение для данного сетевого номера создано, проверяем статус соединения (STAGE)
            // Если IKE соединение установлено (STAGE == 4), то упаковывем пакет и отправляем
            if(ikev2_sa_a->stage == IKE_STAGE_4) {
                esp_mmt_encapsul_data(ikev2_sa_a, data_in, len_data_in, data_out, len_data_out, 4);
                result = IKE_OK;
            }
            // Если соединение еще не установлено, сохраняем пакет для последующей передачи (а может не сохраняем ?)
            else {
                //save_packet(net_num, data_in, len_data_in);
                result = NOT_SEND;
            }
            break;
        }
        default: {
            return NOT_SEND;
        }
    }

    return result;
}

/*
 * Функция проверки созданных соединений
 * Если с соединения давно не приходили данные отправляем пакет keepalive
 * Если на пакеты keepalive не было ответа, закрываем соединение
 * Выход:
 *  результат проверки
 *  data_out - пакет keepalive
 *  len_data_out - размер data_out
 */
unsigned int check_ikev2_sa_a(unsigned char **data_out, int *len_data_out) {
    IKEV2_SA_ADDITINAL_CHAIN * head = ikev2_sa_additional_buf;
    time_t time_now = time(0);

    *(len_data_out) = 0;
    *(data_out) = NULL;
    while(head) {
        if (head->value->role) {
            if (time_now - head->last_time_response > TIME_BETWEEN_RESPONSE_I) {
                if(head->value->stage != IKE_STAGE_4) {
                    // соединение не было установлено в течении TIME_BETWEEN_RESPONSE_I секунд
                    delete_item(head->value, &ikev2_sa_additional_buf);
                    return IKE_ADDITIONAL_DELETE;
                }


                if (time_now - head->last_time_keepalive > TIME_BETWEEN_KEEPALIVE) {
                    head->count_keepalive++;
                    if (head->count_keepalive > MAX_KEEPALIVE) {
                        // Делаем вывод что другой клиент отключен
                        // Удаляем установленное соединение
                        delete_item(head->value, &ikev2_sa_additional_buf);
                        return IKE_ADDITIONAL_DELETE;
                    } else {
                        // Генерация пакета keepalive
                        mmt_get_keepalive(head->value, data_out, len_data_out);
                        head->last_time_keepalive = time_now;
                        break;
                    }
                }
            }
        } else {
            if (time_now - head->last_time_response > TIME_BETWEEN_RESPONSE_R) {
                delete_item(head->value, &ikev2_sa_additional_buf);
                return IKE_ADDITIONAL_DELETE;
            }
        }
        head = head->next;
    }
    return IKE_OK;
}
/*
 * Функция определения сетевого номера сети по ip адресу назначения
 * Вход:
 *  dest_ip - ipадрес назначения
 * Выход:
 *  результат работы
 *  net_num - определенный сетевой номер
 *
 */
unsigned int search_netnum_by_ipnetwork(unsigned int dest_ip, unsigned short * net_num) {
    unsigned int ip_network;
    dest_ip = reverse32(dest_ip);
    mmt_TUNNEL_CHAIN * temp_tunnels = ikev2_tunnels;

    if(temp_tunnels == NULL)
        return IKE_ERR_TUNNELS_BUF_EMPTY;

    while(temp_tunnels) {
        ip_network = dest_ip & temp_tunnels->tunnel->mask_net;
        if(ip_network == temp_tunnels->tunnel->ip_net) {
            *net_num = temp_tunnels->tunnel->net_num;
            return IKE_OK;
        }

        temp_tunnels = temp_tunnels->next;
    }

    return IKE_ERR;
}

/*
 * Функция определяет наличие туннеля с заданным сетевым номером
 * Вход:
 *  net_num - сетевой номер
 * Выход:
 *  Результат
 */
unsigned int tunnels_have_nn(unsigned short net_num) {
    mmt_TUNNEL_CHAIN * temp_tunnels = ikev2_tunnels;

    if(temp_tunnels == NULL)
        return IKE_ERR_TUNNELS_BUF_EMPTY;

    while(temp_tunnels) {
        if(net_num == temp_tunnels->tunnel->net_num) {
            return IKE_OK;
        }
        temp_tunnels = temp_tunnels->next;
    }

    return IKE_ERR;
}

/*
 * Функция проверки принятого пакета IKE_SA_INIT
 * Если устройство инициатор, после проверки формирует пакет IKE_SA_INIT
 * Если устройство ответчик, после проверки формирует пакет IKE_SA_AUTH
 * Вход:
 *     data_in - пакет IKE_SA_INIT
 *     len_data_in - размер data_in
 * Выход:
 *     результат проверки
 *     data_out - пакет IKE_SA_INIT ИЛИ пакет IKE_SA_AUTH
 *     len_data_out - размер data_out
 */
unsigned int mmt_check_ike_sa_a_init(unsigned char *data_in, int len_data_in,
                                     unsigned char **data_out, int *len_data_out) {
    unsigned int T[32], result;
    unsigned char temp[24];
    unsigned char * tempData;
    unsigned int tempLen;
    unsigned int isResponder;
    unsigned short netNum;
    int indexKeySA;
    IKEv2_STRUCT_SA * ikev2_sa = ikev2_sa_pull[index_main_ikev2_sa].ikev2_sa;

    IKEv2_STRUCT_SA * ikev2_sa_a;
    ikev2_block_HDR block_HDR;
    ikev2_block_SA block_SA;
    ikev2_block_KE block_KE;
    ikev2_block_NONCE block_NONCE;
    ikev2_block_NOTIFY block_NOTIFY;

    tempData = data_in;
    tempLen  = len_data_in;

    createBlockHDRfromBuf(data_in, &block_HDR);
    tempData += ikev2_SIZE_HDR;
    tempLen -= ikev2_SIZE_HDR;
    // Поиск по SPI существующего соединения
    isResponder = get_ikev2_sa_a_by_spi(&ikev2_sa_a, block_HDR.initSPI);

    if(isResponder) {
        // Мы ответчик
        // Отбрасываем, если INIT не для нас
        if(*((unsigned short*)(block_HDR.initSPI) + 2) != ikev2_sa->netNumber)
            return IKE_ERR;

        netNum = *((unsigned short*)(block_HDR.initSPI) + 1); // Сетевой номер инициатора

        if(result = tunnels_have_nn(netNum)) // роверка наличия в сетевых настройках канала для сетевого номера
            return result;

        get_ikev2_sa_a_by_nn(netNum, &ikev2_sa_a);

        // Инициализация ikev2_sa_a в качестве ответчика
        ikev2_sa_a_init(ikev2_sa_a, IKE_RESPONDER, ikev2_sa->netNumber, netNum);
        memcpy(ikev2_sa_a->initSPI,  block_HDR.initSPI, 8);
    }
    else {
        // Мы инициатор
        if (ikev2_sa_a->stage != IKE_STAGE_1)
            return IKE_ERR;
        memcpy(ikev2_sa_a->respSPI, block_HDR.respSPI, 8);
    }

    // Собираем из данных блок SA
    if (result = createBlockSAfromBuf(tempData, tempLen, &block_SA))
        return result;
    // Проверка Блока SA
    if (block_SA.nextPayload != ikev2_np_ke)
        return IKE_ERR_SA_NP;
    tempData += block_SA.length;
    tempLen -= block_SA.length;
    if (result = createBlockKEfromBuf(tempData, tempLen, &block_KE))
        return result;

    indexKeySA = -1;

    if (!memcmp(ikev2_sa_a->blockNote.name, block_KE.KE_Data, 8)) {
        if (!memcmp(ikev2_sa_a->blockNote.Nserial, block_KE.KE_Data + 8, 8)) {
            if (ikev2_sa_a->blockNote.numOfKompl >= *(unsigned short *) (block_KE.KE_Data + 16)) {
                indexKeySA = *(unsigned short *) (block_KE.KE_Data + 16);
            }
        }
    }

    if (indexKeySA == -1)
        return IKE_ERR_INDEX_KEY_SA;

    tempData += block_KE.length;
    tempLen -= block_KE.length;
    if(result = createBlockNoncefromBuf(tempData, tempLen, &block_NONCE))
        return result;

    ikev2_sa_a->haveNAT = 1;
    if(block_NONCE.nextPayload == ikev2_np_notify) {
        // Собираем из данных блок N1
        // Потом возвращать код ошибки
        tempData += block_NONCE.length;
        tempLen -= block_NONCE.length;
        if (result = createBlockNotifyfromBuf(tempData, tempLen, &block_NOTIFY))
            return result;

        if (block_NOTIFY.notifyMessageType != NAT_DETECTION_SOURCE_IP) {
            return IKE_ERR_NOTIFY_MT;
        }

        //Расчет CRC32
        unsigned char *crcdata = (unsigned char *) malloc(24);
        memcpy(crcdata, ikev2_sa_a->initSPI, 8);
        memcpy(crcdata + 8, (data_in - 20), 8);
        memcpy(crcdata + 16, (unsigned char *) &ikev2_sa_a->wanIpAdr, 4);
        memcpy(crcdata + 20, (unsigned char *) &ikev2_sa_a->wanPort, 2);
        crcdata[22] = 0;
        crcdata[23] = 0;

        unsigned int crc;
        /*unsigned int crc = crc32(crcdata, 24);
        if (memcmp(block_NOTIFY.Notify_Data, (unsigned char *) &crc, 4)) {
            // Нет проверки
        }*/

        // Собираем из данных блок N2        tempData += block_NOTIFY.length;
        tempLen -= block_NOTIFY.length;
        tempData += block_NONCE.length;
        // Потом возвращать код ошибки
        if (result = createBlockNotifyfromBuf(tempData, tempLen, &block_NOTIFY))
            return result;

        if (block_NOTIFY.notifyMessageType != NAT_DETECTION_DESTINATION_IP) {
            return IKE_ERR_NOTIFY_MT;
        }

        memcpy(crcdata + 16, (unsigned char *) &ikev2_sa_a->lanIpAdr, 4);
        memcpy(crcdata + 20, (unsigned char *) &ikev2_sa_a->lanPort, 2);
        crc = crc32(crcdata, 24);
        free(crcdata);
        if (memcmp(block_NOTIFY.Notify_Data, (unsigned char *) &crc, 4)) {
            ikev2_sa_a->haveNAT = 0;
        }
        else {
            ikev2_sa_a->haveNAT = 1;
        }
    }

    ikev2_sa_a->indexKeySA = indexKeySA;

    // Чтение ключа
    jclass SIMDVS = (*ENV)->GetObjectClass(ENV, THIS);
    jmethodID getIndividKey = (*ENV)->GetMethodID(ENV, SIMDVS, "getIndividKey", "(S[B)Z");
    jbyteArray buf = (*ENV)->NewByteArray(ENV, 32);
    jshort numKey = ikev2_sa_a->indexKeySA;
    jboolean result2 = (*ENV)->CallBooleanMethod(ENV, THIS, getIndividKey, numKey, buf);

    if (!result2) {
        return IKE_ERR_CRIPT_KEY;
    }

    // Сохранение ключа
    uint8_t isCp;
    uint8_t *jkey = (uint8_t *) (*ENV)->GetByteArrayElements(ENV, buf, &isCp);
    memcpy(ikev2_sa_a->blockNote.key, jkey, 32);

    if(ikev2_sa_a->SecureIdentifyInf != NULL)
        free(ikev2_sa_a->SecureIdentifyInf);
    ikev2_sa_a->SecureIdentifyInf = (unsigned char *)malloc(264);
    init_updsch((unsigned char *)ikev2_sa_a->blockNote.key_dsh,
                (unsigned char *)ikev2_sa_a->blockNote.key,
                (unsigned char *)ikev2_sa_a->blockNote.Table,
                ikev2_sa_a->SecureIdentifyInf,
                (unsigned char *)&(ikev2_sa_a->blockNote));

    if(isResponder) {
        if (ikev2_sa_a->nonceI != NULL) {
            free(ikev2_sa_a->nonceI);
            ikev2_sa_a->nonceI = NULL;
        }
        ikev2_sa_a->nonceI = (unsigned char *) malloc(block_NONCE.length - 4);
        memcpy(ikev2_sa_a->nonceI, block_NONCE.N_Data, block_NONCE.length - 4);
    }
    else {
        if (ikev2_sa_a->nonceR != NULL) {
            free(ikev2_sa_a->nonceR);
            ikev2_sa_a->nonceR = NULL;
        }
        ikev2_sa_a->nonceR = (unsigned char *) malloc(block_NONCE.length - 4);
        memcpy(ikev2_sa_a->nonceR, block_NONCE.N_Data, block_NONCE.length - 4);
    }
    ikev2_sa_a->stage = IKE_STAGE_2;

    // Выработка сеансовых ключей
    memcpy(temp, ikev2_sa_a->nonceI, 8);
    memcpy(temp + 8, ikev2_sa_a->nonceR, 8);
    temp[16] = 1;
    memset(temp + 17, 0, 7);
    memset((unsigned char *) T, 0, 32 * 4);
	
#if defined(CRYPT_GOST28147)	
    GostStruct Cript;
    Cript.REGIM = MAKE_IMZ;
    Cript.Key = ikev2_sa_a->blockNote.key;
    Cript.LenIMZ = LEN_IMZ_4;
    Cript.Din = temp;
    Cript.Dout = (unsigned char *) &T[0];
    Cript.LenBytes = 24;
    Cript.TR_STATE = TR_NO;
    Cript.Tz = (unsigned char *) ikev2_sa_a->blockNote.Table;
    Gost28147(&Cript);
#elif defined(CRYPT_MAGMA)
    unsigned char imit_ctx[kImit89ContextLen];
    if(!cypher_magma_imit_init((unsigned char *)ikev2_sa_a->blockNote.key, LEN_IMZ_4, imit_ctx))
        return IKE_ERR_MAGMA_IMIT_INIT;
    if(!cypher_imit(imit_ctx, temp, (unsigned char *) &T[0], 24))
        return IKE_ERR_MAGMA_IMIT;
    free_imit(imit_ctx);
#endif

    for (int i = 1; i < 32; i++) {
        memcpy(temp, (unsigned char *) &T[i - 1], 4);
        memcpy(temp + 4, ikev2_sa_a->nonceI, 8);
        memcpy(temp + 12, ikev2_sa_a->nonceR, 8);
        temp[20] = i + 1;
        memset(temp + 21, 0, 3);
		
#if defined(CRYPT_GOST28147)			
        Cript.Din = temp;
        Cript.Dout = (unsigned char *) &T[i];
        Cript.LenBytes = 24;
        Gost28147(&Cript);
#elif defined(CRYPT_MAGMA)
        if(!cypher_magma_imit_init((unsigned char *)ikev2_sa_a->blockNote.key, LEN_IMZ_4, imit_ctx))
            return IKE_ERR_MAGMA_IMIT_INIT;
        if(!cypher_imit(imit_ctx, temp, (unsigned char *) &T[i], 24))
            return IKE_ERR_MAGMA_IMIT;
        free_imit(imit_ctx);
#endif
    }

    memcpy((unsigned char *) &ikev2_sa_a->Kei, (unsigned char *) T, 32);
    memcpy((unsigned char *) &ikev2_sa_a->Ker, (unsigned char *) (T + 8), 32);
    memcpy((unsigned char *) &ikev2_sa_a->Kai, (unsigned char *) (T + 16), 32);
    memcpy((unsigned char *) &ikev2_sa_a->Kar, (unsigned char *) (T + 24), 32);


    if(isResponder) {
        // формирование пакета INIT
        get_ike_sa_a_init(ikev2_sa_a, data_out, len_data_out);
    }
    else {
        // формирование пакета AUTH
        get_ike_sa_a_auth(ikev2_sa_a, data_out, len_data_out);
    }
    return IKE_OK;
}

/*
 * Функция проверки принятого пакета IKE_SA_AUTH
 * Если устройство инициатор, после проверки формирует сохраненный IP-пакет
 * Если устройство ответчик, после проверки формирует ответный пакет IKE_SA_AUTH
 * Вход:
 *     data_in - пакет IKE_SA_AUTH
 *     len_data_in - размер data_in
 * Выход:
 *     результат проверки
 *     data_out - сохраненный IP-пакет ИЛИ пакет IKE_SA_AUTH
 *     len_data_out - размер data_out
 */

unsigned int mmt_check_ike_sa_a_auth(unsigned char *data_in, int len_data_in,
                                     unsigned char **data_out, int *len_data_out) {
    unsigned int result;
    unsigned char izv[8];
    unsigned int isInitiator;
    unsigned char * tempData;
    unsigned int tempLen;

    IKEv2_STRUCT_SA * ikev2_sa_a;
    ikev2_block_HDR block_HDR;


    tempData = data_in;
    tempLen = len_data_in;

    createBlockHDRfromBuf(data_in, &block_HDR);
    tempData += ikev2_SIZE_HDR;
    tempLen -= ikev2_SIZE_HDR;

    if(result = get_ikev2_sa_a_by_spi(&ikev2_sa_a, block_HDR.initSPI)) {
        return result;
    }

    isInitiator = ikev2_sa_a->role;
	
#if defined(CRYPT_GOST28147)		
	GostStruct Cript;
    Cript.REGIM = MAKE_IMZ;
    Cript.Din = data_in;
    Cript.LenIMZ = LEN_IMZ_8;
    Cript.Dout = izv;
    Cript.LenBytes = 40;
    Cript.TR_STATE = 0;
    Cript.Tz = (unsigned char *) ikev2_sa_a->blockNote.Table;
#endif
    if(isInitiator) {
        // Мы инициатор
        if (ikev2_sa_a->stage != IKE_STAGE_3)return IKE_ERR;
		
#if defined(CRYPT_GOST28147)	
        Cript.Key = ikev2_sa_a->Kar;
        Gost28147(&Cript);
#elif defined(CRYPT_MAGMA)
        unsigned char imit_ctx[kImit89ContextLen];
        if(!cypher_magma_imit_init((unsigned char *)ikev2_sa_a->Kar, LEN_IMZ_8, imit_ctx))
            return IKE_ERR_MAGMA_IMIT_INIT;
        if(!cypher_imit(imit_ctx, data_in, izv, 40))
            return IKE_ERR_MAGMA_IMIT;
        free_imit(imit_ctx);
#endif
        if(memcmp(izv, data_in + 40, 8)) {
            return IKE_ERR_IMZ_HDR;
        }
        if(result = check_ike_sa_a_auth(ikev2_sa_a, tempData, tempLen)) {
            return result;
        }
        // Отправка сохраненного пакета
        mmt_WAIT_PACKET * wait_packet = get_wait_packet(&wait_packet_buf,
                                                        ikev2_sa_a->serverNetNumber);

        if(!esp_mmt_encapsul_data(ikev2_sa_a, wait_packet->data, wait_packet->len_data, data_out, len_data_out, 4))
            return IKE_SEND;
        else
            return IKE_ERR;
    }
    else {
        // Мы ответчик
        if (ikev2_sa_a->stage != IKE_STAGE_2) return IKE_ERR;
#if defined(CRYPT_GOST28147)	
        Cript.Key = ikev2_sa_a->Kai;
        Gost28147(&Cript);
#elif defined(CRYPT_MAGMA)
        unsigned char imit_ctx[kImit89ContextLen];
        if(!cypher_magma_imit_init((unsigned char *)ikev2_sa_a->Kai, LEN_IMZ_8, imit_ctx))
            return IKE_ERR_MAGMA_IMIT_INIT;
        if(!cypher_imit(imit_ctx, data_in, izv, 40))
            return IKE_ERR_MAGMA_IMIT;
        free_imit(imit_ctx);
#endif
        if(memcmp(izv, data_in + 40, 8)) {
            return IKE_ERR_IMZ_HDR;
        }

        if(result = check_ike_sa_a_auth(ikev2_sa_a, tempData, tempLen)){
            return result;
        }
        // формирование пакета AUTH
        get_ike_sa_a_auth(ikev2_sa_a, data_out, len_data_out);
        return IKE_SEND;
    }
}

/*
 * Функция инициализации дополнительного IKE соединения
 * Вход:
 *  ikev2_sa_a - IKE соединение
 *  role - роль устройства в IKE соединении
 *  netNum - сетевой номер устройства
 *  server_net_number - сетевой номер сервера
 */
void ikev2_sa_a_init(IKEv2_STRUCT_SA *ikev2_sa_a, unsigned char role,
                              unsigned short net_num, unsigned short server_net_number) {
    TRANSFORM * transf;
    PROPOSAL * proposal;
    IKEv2_STRUCT_SA * ikev2_sa = ikev2_sa_pull[index_main_ikev2_sa].ikev2_sa;

    transf = (TRANSFORM *)malloc(sizeof(TRANSFORM) * 2);
    transf[0].type = 1;
    transf[0].id = 1024;
    transf[1].type = 3;
    transf[1].id = 1024;
    proposal = (PROPOSAL *)malloc(sizeof(PROPOSAL));
    proposal->num_transf = 2;
    proposal->transforms = transf;

    memset((unsigned char*)ikev2_sa_a, 0 , sizeof(IKEv2_STRUCT_SA));

    ikev2_sa_a->stage = IKE_STAGE_0;
    // Составление SPI
    if(role == IKE_INITIATOR) {
        *(unsigned short*)(ikev2_sa_a->initSPI) 	   = (unsigned short) (rand() % 0xFFFF);
        *((unsigned short*)(ikev2_sa_a->initSPI) + 1) = net_num;
        *((unsigned short*)(ikev2_sa_a->initSPI) + 2) = server_net_number;
        *((unsigned short*)(ikev2_sa_a->initSPI) + 3) = (unsigned short) (rand() % 0xFFFF);
        ikev2_sa_a->nonceI = (unsigned char *)malloc(8);
        //Генерация нонса
        //*(unsigned int *)ikev2_sa_a->nonceI	= random();
        //*(unsigned int *)(ikev2_sa_a->nonceI+4)	= random();
        nonce_get((unsigned int *)ikev2_sa_a->nonceI);
        //memcpy(ikev2_sa_a->nonceI, get_random(ikev2_sa_a->SecureIdentifyInf), 8);
    }
    else {
        *(unsigned short*)(ikev2_sa_a->respSPI) 	  = (unsigned short) (rand() % 0xFFFF);
        *((unsigned short*)(ikev2_sa_a->respSPI) + 1) = net_num;
        *((unsigned short*)(ikev2_sa_a->respSPI) + 2) = server_net_number;
        *((unsigned short*)(ikev2_sa_a->respSPI) + 3) = (unsigned short) (rand() % 0xFFFF);
        ikev2_sa_a->nonceR = (unsigned char *)malloc(8);
        //Генерация нонса
        //*(unsigned int *)ikev2_sa_a->nonceR	= random();
        //*(unsigned int *)(ikev2_sa_a->nonceR+4)	= random();
        nonce_get((unsigned int *)ikev2_sa_a->nonceR);
        //memcpy(ikev2_sa_a->nonceR, get_random(ikev2_sa_a->SecureIdentifyInf), 8);
    }

    ikev2_sa_a->num_prop = 1;
    ikev2_sa_a->proposals = proposal;

    KEY_KOMPL  blockNote;
    memcpy((unsigned char *)&blockNote, (unsigned char *)&ikev2_sa->blockNote, sizeof(KEY_KOMPL));
    ikev2_sa_a->blockNote = blockNote;
    ikev2_sa_a->lanPort = ikev2_sa->lanPort;
    memcpy(ikev2_sa_a->lanIpAdr, ikev2_sa->lanIpAdr, 4);
    ikev2_sa_a->wanPort = ikev2_sa->wanPort;
    memcpy(ikev2_sa_a->wanIpAdr, ikev2_sa->wanIpAdr, 4);
    ikev2_sa_a->netNumber = net_num;
    ikev2_sa_a->serverNetNumber = server_net_number;
    ikev2_sa_a->indexKeySA = -1;
    ikev2_sa_a->role = role;
}

/*
 * Функция проверки данных пакета IKE_SA_AUTH
 * Вход:
 *  ikev2_sa_a - контекст IKE
 *  data - пакет IKE_SA_AUTH
 *  lenData - размер data
 * Выход:
 *  Результат проверки
 */
unsigned int check_ike_sa_a_auth(IKEv2_STRUCT_SA *ikev2_sa_a, unsigned char *data, int lenData) {
    ikev2_block_SA block_SA;
    ikev2_block_SK block_SK;
    ikev2_block_AUTH block_AUTH;
    ikev2_block_IDENT block_IDENT;
    unsigned char izv[8];
    unsigned int A[4], result;;
    unsigned char temp[32];

    unsigned char * tempData = data;
    int tempLen = lenData;
    // Собираем из данных блок SK
    // Потом возвращать код ошибки
    if(result = createBlockSKfromBuf(tempData, tempLen, &block_SK))
        return result;

    //Проверка блока SK
    if(ikev2_sa_a->role == IKE_INITIATOR) {
        if (block_SK.nextPayload != ikev2_np_idr) return IKE_ERR_SK_NP;
    }
    else {
        if (block_SK.nextPayload != ikev2_np_idi) return IKE_ERR_SK_NP;
    }

#if defined(CRYPT_GOST28147)	
    // Убрать лишние присваивания
    // Расшифрование
    GostStruct Cript;
    Cript.REGIM		= GAMMIROVANIE_OS_REG;
    Cript.CRYPT		= DECRYPT;
    Cript.Key		= ikev2_sa_a->role ? ikev2_sa_a->Ker : ikev2_sa_a->Kei;
    Cript.Sp		= (unsigned int *)&block_SK.VI;
    Cript.Din		= block_SK.encrData;
    Cript.Dout		= block_SK.encrData;
    Cript.LenBytes	= block_SK.length - 28; //4 - заголовок, 8 - синхропосылка, 8 - изв, 8 - имитовставка
    Cript.TR_STATE	= TR_NO;
    Cript.Tz		= (unsigned char *)ikev2_sa_a->blockNote.Table;
    Gost28147(&Cript);

    // Расчет имитовставки
    Cript.REGIM		= MAKE_IMZ;
    Cript.Key       = ikev2_sa_a->role ? ikev2_sa_a->Ker : ikev2_sa_a->Kei;
    Cript.LenIMZ	= LEN_IMZ_8;
    Cript.Din		= block_SK.encrData;
    Cript.Dout		= izv;
    Cript.LenBytes	= block_SK.length - 28;
    Cript.TR_STATE	= TR_NO;
    Cript.Tz		= (unsigned char *)ikev2_sa_a->blockNote.Table;
    Gost28147(&Cript);
#elif defined(CRYPT_MAGMA)
    unsigned char ctx[kCfb89ContextLen];
    if(!cypher_magma_cfb_init((unsigned char *)ikev2_sa_a->role ? ikev2_sa_a->Ker : ikev2_sa_a->Kei, ctx, kBlockLen89, (unsigned char *)&block_SK.VI, 8))
        return IKE_ERR_MAGMA_CFB_INIT;
    /*if(!cypher_decr_cfb(ctx, block_SK.encrData, block_SK.encrData, block_SK.length - 28))
        return IKE_ERR_MAGMA_DECR;*/

    int len_temp_buf = block_SK.length - 28;
    unsigned char * temp_buffer = (unsigned char * )malloc(len_temp_buf);
    if(!cypher_decr_cfb(ctx, block_SK.encrData, temp_buffer, len_temp_buf))
        return IKE_ERR_MAGMA_DECR;
    memcpy(block_SK.encrData, temp_buffer, len_temp_buf);
    free(temp_buffer);
    free_cfb(ctx);

    unsigned char imit_ctx[kImit89ContextLen];
    if(!cypher_magma_imit_init((unsigned char *)ikev2_sa_a->role ? ikev2_sa_a->Ker : ikev2_sa_a->Kei, LEN_IMZ_8, imit_ctx))
        return IKE_ERR_MAGMA_IMIT_INIT;
    if(!cypher_imit(imit_ctx, block_SK.encrData, izv, block_SK.length - 28))
        return IKE_ERR_MAGMA_IMIT;
    free_imit(imit_ctx);
#endif
    if(memcmp(izv, data + (block_SK.length-8), 8)) {
        return IKE_ERR_IMZ_SK;
    }

    tempData = block_SK.encrData;
    tempLen = (block_SK.length - 28)			        // Длина зашифрованных данных (и заполнения)
              - block_SK.encrData[block_SK.length-29]   // Длина заполнения
              - 1;									    // Длина поля "Длина заполнения"

    // Собираем из данных блок IDr
    // Потом возвращать код ошибки
    if(result = createBlockIDfromBuf(tempData, tempLen, &block_IDENT))
        return result;

    // Проверка блока IDr
    // NextPaload должен быть AUTH
    if(block_IDENT.nextPayload != ikev2_np_auth)
        return IKE_ERR_ID_NP;
    // Проверка ID Type. На данный момент поддерживается только 201
    if(block_IDENT.idType != 201)
        return IKE_ERR_ID_IDTYPE;

    // Собираем из данных блок AUTH
    tempData += block_IDENT.length;
    tempLen  -= block_IDENT.length;
    if(result = createBlockAUTHfromBuf(tempData, tempLen, &block_AUTH))
        return result;

    // Проверка блока AUTH
    // NextPaload должен быть CP
    if(block_AUTH.nextPayload != ikev2_np_sa)
        return IKE_ERR_AUTH_NP;
    // Проверка Auth Method. На данный момент поддерживается только 201
    if(block_AUTH.A_Method != 201)
        return IKE_ERR_AUTH_AMET;

    // Собираем из данных блок SA
    tempData += block_AUTH.length;
    tempLen  -= block_AUTH.length;
    if(result = createBlockSAfromBuf(tempData, tempLen, &block_SA))
        return result;
    if(ikev2_sa_a->role == IKE_INITIATOR)
        ikev2_sa_a->espRespSPI = block_SA.proposals[0].spi;
    else
        ikev2_sa_a->espInitSPI = block_SA.proposals[0].spi;

    //Расчет AUTHr
    memset(temp, 0 , 32);
    memcpy(temp  , ikev2_sa_a->initSPI, 8);
    memcpy(temp+8, ikev2_sa_a->respSPI, 8);
    if(ikev2_sa_a->role == IKE_INITIATOR) {
        memcpy(temp + 16, (unsigned char *) &ikev2_sa_a->espRespSPI, 4);
        temp[20] = 5;
    }
    else {
        memcpy(temp + 16, (unsigned char *) &ikev2_sa_a->espInitSPI, 4);
        temp[20] = 1;
    }
	
#if defined(CRYPT_GOST28147)	
    Cript.REGIM		= MAKE_IMZ;
    Cript.Key       = ikev2_sa_a->role ? ikev2_sa_a->Kar : ikev2_sa_a->Kai;
    Cript.LenIMZ	= LEN_IMZ_4;
    Cript.Din		= temp;
    Cript.Dout		= (unsigned char *)&A[0];
    Cript.LenBytes	= 24;
    Cript.TR_STATE	= TR_NO;
    Cript.Tz		= (unsigned char *)ikev2_sa_a->blockNote.Table;
    Gost28147(&Cript);
#elif defined(CRYPT_MAGMA)
    if(!cypher_magma_imit_init((unsigned char *)ikev2_sa_a->role ? ikev2_sa_a->Kar : ikev2_sa_a->Kai, LEN_IMZ_4, imit_ctx))
        return IKE_ERR_MAGMA_IMIT_INIT;
    if(!cypher_imit(imit_ctx, temp, (unsigned char *)&A[0],24))
        return IKE_ERR_MAGMA_IMIT;
    free_imit(imit_ctx);
#endif
    memcpy(temp+4, ikev2_sa_a->initSPI, 8);
    memcpy(temp+12, ikev2_sa_a->respSPI, 8);
    if(ikev2_sa_a->role == IKE_INITIATOR)
        memcpy(temp + 20, (unsigned char *) &ikev2_sa_a->espRespSPI, 4);
    else
        memcpy(temp + 20, (unsigned char *) &ikev2_sa_a->espInitSPI, 4);

    for(int i = 1; i < 4; i++) {
        memcpy(temp  , (unsigned char *)&A[i-1], 4);
        temp[24]        = ikev2_sa_a->role ? i+5 : i+1;
#if defined(CRYPT_GOST28147)	
        Cript.Din		= temp;
        Cript.Dout		= (unsigned char *)&A[i];
        Cript.LenBytes	= 32;
        Cript.TR_STATE	= TR_NO;
        Gost28147(&Cript);
#elif defined(CRYPT_MAGMA)
        if(!cypher_magma_imit_init((unsigned char *)ikev2_sa_a->role ? ikev2_sa_a->Kar : ikev2_sa_a->Kai, LEN_IMZ_4, imit_ctx))
            return IKE_ERR_MAGMA_IMIT_INIT;
        if(!cypher_imit(imit_ctx, temp, (unsigned char *)&A[i],32))
            return IKE_ERR_MAGMA_IMIT;
        free_imit(imit_ctx);
#endif
    }

    memcpy(temp,A,16);

    // Сравнение
    if(memcmp(temp, block_AUTH.A_Data, 8) || memcmp(temp+8, block_AUTH.A_Data+8, 8)) {
        return IKE_ERR_AUTHDATA;
    }


    // Сохранение силектора трафика
    /*if(block_SA.nextPayload == ikev2_np_TSi) {
        tempData += block_SA.length;
        tempLen  -= block_SA.length;
        if(result = createBlockTRAFSELECTSfromBuf(tempData, tempLen, &block_TRAF_SELECTSi))
            return result;


        ikev2_sa_a->numSTi = block_TRAF_SELECTSi.numOfTSs;
        ikev2_sa_a->TSi = (TRAF_SELECT *)malloc(sizeof(TRAF_SELECT) * ikev2_sa_a->numSTi);
        for(int i = 0; i < ikev2_sa->numSTi; i++) {
            ikev2_sa_a->TSi[i].startPort = block_TRAF_SELECTSi.ID_Data[i].start_port;
            ikev2_sa_a->TSi[i].endPort = block_TRAF_SELECTSi.ID_Data[i].end_port;
            ikev2_sa_a->TSi[i].startAdd = block_TRAF_SELECTSi.ID_Data[i].start_address;
            ikev2_sa_a->TSi[i].endAdd = block_TRAF_SELECTSi.ID_Data[i].end_address;
        }

        if(block_TRAF_SELECTSi.nextPayload == ikev2_np_TSr) {
            tempData += block_TRAF_SELECTSi.length;
            tempLen  -= block_TRAF_SELECTSi.length;
            if(result = createBlockTRAFSELECTSfromBuf(tempData, tempLen, &block_TRAF_SELECTSr))
                return result;

            ikev2_sa_a->numSTr = block_TRAF_SELECTSr.numOfTSs;
            ikev2_sa_a->TSr = (TRAF_SELECT *)malloc(sizeof(TRAF_SELECT) * ikev2_sa_a->numSTr);
            for(int i = 0; i < ikev2_sa->numSTr; i++) {
                ikev2_sa_a->TSr[i].startPort = block_TRAF_SELECTSr.ID_Data[i].start_port;
                ikev2_sa_a->TSr[i].endPort = block_TRAF_SELECTSr.ID_Data[i].end_port;
                ikev2_sa_a->TSr[i].startAdd = block_TRAF_SELECTSr.ID_Data[i].start_address;
                ikev2_sa_a->TSr[i].endAdd = block_TRAF_SELECTSr.ID_Data[i].end_address;
            }
        }
    }

    ikev2_sa_a->IP_addr = ikev2_sa_a->TSi[0].startAdd;
    int m = 0, n = 32;
    unsigned int razn = ikev2_sa_a->TSr[0].endAdd - ikev2_sa_a->TSr[0].startAdd;
    while(n) {
        if(razn != 0)
            m++;
        else
            break;
        razn = razn >> 1;
        n--;
    }
    ikev2_sa_a->IP_mask 		= 32 - m;
    */
    ikev2_sa_a->stage		= IKE_STAGE_4;
    ikev2_sa_a->inMessageID	= 2;
    ikev2_sa_a->outMessageID= 2;
    ikev2_sa_a->inSNESP		= 0;
    ikev2_sa_a->outSNESP	= 0;
    return IKE_OK;
}

/*
 * Функция по сетевому номеру сервера находит или создает новый IKE контекст.
 * Вход:
 *  server_net_number - сетевой номер сервера
 * Выход
 *  результат работы
 *  ikev2_sa_a - IKE контекст
 */
unsigned int get_ikev2_sa_a_by_nn(unsigned short server_net_number, IKEv2_STRUCT_SA **ikev2_sa_a) {
    IKEV2_SA_ADDITINAL_CHAIN * head = ikev2_sa_additional_buf;
    while(head) {
        if(head->value->serverNetNumber == server_net_number) {
            // Для данного сетевого номера соединение уже создано
            (*ikev2_sa_a) = head->value;
            return IKEv2_OLD;
        }
        head = head->next;
    }

    // Соединение для данного сетевого номера не найдено
    *ikev2_sa_a = (IKEv2_STRUCT_SA *)malloc(sizeof(IKEv2_STRUCT_SA));
    memset(*ikev2_sa_a, 0, sizeof(IKEv2_STRUCT_SA));
    push_sa(*ikev2_sa_a, &ikev2_sa_additional_buf);

    return IKEv2_NEW;
}

/*
 * Функция по SPI инициатора находит IKE контекст.
 * При нахождении обвновляет временные метки
 * Вход:
 *  spi - SPI инициатора
 * Выход
 *  результат работы
 *  ikev2_sa_a - IKE контекст
 */
unsigned int get_ikev2_sa_a_by_spi(IKEv2_STRUCT_SA **ikev2_sa_a, unsigned char * spi) {
    IKEV2_SA_ADDITINAL_CHAIN * head = ikev2_sa_additional_buf;
    while(head) {
        if(!memcmp(head->value->initSPI, spi, 8)) {
            // Соединение уже существует для данного SPI
            (*ikev2_sa_a) = head->value;
            head->last_time_response =  head->last_time_keepalive = time(0);
            head->count_keepalive = 0;
            return 0;
        }
        head = head->next;
    }

    return IKE_ERR;
}

/*
 * Функция по ESPSPI инициатора находит IKE контекст.
 * При нахождении обвновляет временные метки
 * Вход:
 *  spi - ESPSPI инициатора
 * Выход
 *  результат работы
 *  ikev2_sa_a - IKE контекст
 */
unsigned int get_ikev2_sa_a_by_espspi(IKEv2_STRUCT_SA **ikev2_sa_a, unsigned int spi) {
    IKEV2_SA_ADDITINAL_CHAIN * head = ikev2_sa_additional_buf;
    while(head) {
        if(head->value->espInitSPI == spi || head->value->espRespSPI == spi) {
            (*ikev2_sa_a) = head->value;
            head->last_time_response = head->last_time_keepalive = time(0);
            head->count_keepalive = 0;
            return 0;
        }
        head = head->next;
    }
    return IKE_ERR;
}

/*
 * Функция формирования пакета IKE_KEEPALIVE
 * Вход:
 *  ikev2_sa_a - IKE контекст
 * Выход:
 *  data_out - пакет IKE_KEEPALIVE
 *  len_data_out - размер data_out
 */
void mmt_get_keepalive(IKEv2_STRUCT_SA * ikev2_sa_a, unsigned char ** dataOut, int * lenDataOut) {
    unsigned char * buffer;

    if(ikev2_sa_a->stage != IKE_STAGE_4) {
        *lenDataOut = 0;
        return;
    }

    buffer = (unsigned char *)malloc(ikev2_SIZE_HDR + 4 + ikev2_SIZE_START_ZERO);
    memset(buffer, 0, ikev2_SIZE_HDR + 4 + ikev2_SIZE_START_ZERO);
    buffer += ikev2_SIZE_START_ZERO;
    memcpy(buffer, ikev2_sa_a->initSPI, 8);
    memcpy(buffer+8, ikev2_sa_a->respSPI, 8);

    *(buffer + 16)						= ikev2_np_SK;
    *(buffer + 17)						= 0x20;
    *(buffer + 18)						= INFORMATIONAL;
    *(buffer + 19)						= ikev2_sa_a->role ? 0x08 : 0x20;
    *(unsigned int*)(buffer +20)		= reverse32(ikev2_sa_a->outMessageID);
    *(unsigned int*)(buffer +24)		= reverse32(ikev2_SIZE_HDR+4);
    *(buffer + 28)                      = ikev2_np_not;
    *(buffer + 29)                      = 0;
    *(unsigned short *)(buffer +30)		= reverse16(4);

    ikev2_sa_a->outMessageID++;
    buffer -= ikev2_SIZE_START_ZERO;
    *lenDataOut = ikev2_SIZE_HDR + 4 + ikev2_SIZE_START_ZERO;
    *dataOut = buffer;
}

/*
 *  Функция очистки глобального контейнера дополнительных IKE контекстов
 */
void delete_all_ikev2_sa_a() {
    IKEv2_STRUCT_SA * ikev2_sa;
    if(ikev2_sa_additional_buf == NULL)
        return;

    while(ikev2_sa_additional_buf) {
        ikev2_sa = pop_sa(&ikev2_sa_additional_buf);
        delete_ikev2_sa_a(ikev2_sa);
    }
}

/*
 * Функция удаления всех ожидающих отправки пакетов
 */
void delete_all_wait_packets() {
    mmt_WAIT_PACKET * temp;
    if(wait_packet_buf == NULL)
        return;
    while(wait_packet_buf) {
        temp = pop_wp(&wait_packet_buf);
        free(temp);
    }
}