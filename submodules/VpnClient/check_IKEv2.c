#include <stdlib.h>
#include <string.h>

#include "check_IKEv2.h"
#include "crc32.h"
#include "updsch_manager.h"

#if defined(CRYPT_GOST28147)
	#include "Gost28147.h"
#elif defined(CRYPT_MAGMA)
	#include "cypher.h"
#endif

unsigned int check_block_hdr(ikev2_block_HDR * block_HDR, IKEv2_STRUCT_SA * ikev2_sa) {
	//Проверка поля IKE_SA Init SPI 
	if(memcmp(ikev2_sa->initSPI, block_HDR->initSPI,8))
		return IKE_ERR_HDR_SPI;
	//Проверка поля Nex Payload
	if(!((block_HDR->nextPayload >= ikev2_np_not) && (block_HDR->nextPayload <= ikev2_np_eap)))
		return IKE_ERR_HDR_NP;
	//Проверка поля Ver
	if(block_HDR->vers != 0x20)
		return IKE_ERR_HDR_VER;
	//Проверка поля Flags
	if(block_HDR->flags != 0x20)
		return IKE_ERR_HDR_FLAG;

	//Проверка поля Exchange Type
	switch(block_HDR->exchangeType) {
	case IKE_SA_INIT: {
		if(ikev2_sa->stage != IKE_STAGE_1)
			return IKE_ERR_STAGE;
		if(block_HDR->messageID != 0) 
			return IKE_ERR_MID;
		/*if(block_HDR->nextPayload != ikev2_np_sa) 
			return 1;*/
		break;
	}
	case IKE_AUTH: {
		if(ikev2_sa->stage != IKE_STAGE_3)
			return IKE_ERR_STAGE;
		if(block_HDR->messageID != 1) 
			return IKE_ERR_MID;
		if(block_HDR->nextPayload != ikev2_np_SK)
			return IKE_ERR_HDR_NP;
		break;
	}
	case INFORMATIONAL: {
		if(ikev2_sa->stage != IKE_STAGE_4)
			return IKE_ERR_STAGE;
		if(ikev2_sa->inMessageID > block_HDR->messageID) {
			if ((ikev2_sa->inMessageID - block_HDR->messageID) > ikev2_SIZE_IKE_SN_WINDOW) {
				return IKE_ERR_MID_OVER;
			}
		}
		else {
			ikev2_sa->inMessageID = block_HDR->messageID;
		}
		break;
	}
    case KEEPALIVE: {
        if(ikev2_sa->stage != IKE_STAGE_4)
            return IKE_ERR_STAGE;
		if(ikev2_sa->inMessageID > block_HDR->messageID) {
			if ((ikev2_sa->inMessageID - block_HDR->messageID) > ikev2_SIZE_IKE_SN_WINDOW) {
				return IKE_ERR_MID_OVER;
			}
		}
		else {
			ikev2_sa->inMessageID = block_HDR->messageID;
		}
        break;
    }
	default : {
		return IKE_ERR_ETYPE_UNSUP;
	}
	}

	return IKE_OK;
}

unsigned int ikev2_check_ike_sa_init(unsigned char *data, int lenData, IKEv2_STRUCT_SA * ikev2_sa) {
	unsigned char nextPayload;
    ikev2_block_SA block_SA;
    ikev2_block_KE block_KE;
	ikev2_block_NONCE block_NONCE;
    ikev2_block_NOTIFY block_NOTIFY;
	ikev2_block_VendorID block_VendorID;

	unsigned int T[32], result;
	unsigned char temp[24];

	unsigned char * tempData = data;
	int tempLen = lenData;

    // Собираем из данных блок SA
    if(result = createBlockSAfromBuf(tempData, tempLen, &block_SA))
        return result;

    // Проверка Блока SA
    if(block_SA.nextPayload != ikev2_np_ke)
        return IKE_ERR_SA_NP;

    // Проверка предложений, полученных от сервера
    if(result = checkSavedProposals(&block_SA))
        return result;

    // Собираем из данных блок KE
    tempData += block_SA.length;
    tempLen -= block_SA.length;
    if(result = createBlockKEfromBuf(tempData, tempLen, &block_KE))
        return result;

	int indexKeySA = -1;

	if(!memcmp(ikev2_sa->blockNote.name, block_KE.KE_Data, 8)) {
		if(!memcmp(ikev2_sa->blockNote.Nserial, block_KE.KE_Data+8, 8)) {
			//if(ikev2_sa->blockNote.NKompl == *(unsigned  short *)(block_KE.KE_Data+16)) {
				indexKeySA = *(unsigned  short *)(block_KE.KE_Data+16);
			//}
		}
	}

    if(indexKeySA == -1) return IKE_ERR_INDEX_KEY_SA;

    tempData += block_KE.length;
    tempLen -= block_KE.length;

	ikev2_sa->haveNAT = 1;
	
	// Переделать. В цикле разбирать все блоки
	
	nextPayload = block_KE.nextPayload;

	// Nonce
	if(nextPayload == ikev2_np_nonce) {
		// Соборка из данных блок NONCE
		if(result = createBlockNoncefromBuf(tempData, tempLen, &block_NONCE))
			return result;
		
		nextPayload = block_NONCE.nextPayload;
		tempData += block_NONCE.length;
        tempLen -= block_NONCE.length;
	}
	else {
		return IKE_ERR;
	}

	/* Убрана проверка блоков N1, N2, VendorID */

/*
	// N1
	if(nextPayload == ikev2_np_notify) {
		if (result = createBlockNotifyfromBuf(tempData, tempLen, &block_NOTIFY))
            return result;
		
		nextPayload = block_NOTIFY.nextPayload;
		tempLen -= block_NOTIFY.length;
		tempData += block_NOTIFY.length;
	}
	else {
		return IKE_ERR;
	}

	// N2
	if(nextPayload == ikev2_np_notify) {
		if (result = createBlockNotifyfromBuf(tempData, tempLen, &block_NOTIFY))
			return result;

		nextPayload = block_NOTIFY.nextPayload;
		tempLen -= block_NOTIFY.length;
		tempData += block_NOTIFY.length;
	}
	else {
		return IKE_ERR;
	}

	// VendorID
	if(nextPayload == ikev2_np_vendor) {
		if (result = createBlockVendorIDfromBuf(tempData, tempLen, &block_VendorID))
            return result;
		
		nextPayload = block_VendorID.nextPayload;
		tempLen -= block_VendorID.length;
		tempData += block_VendorID.length;
	}
	else {
		//return IKE_ERR;
	}

*/
	
	
    /*if(block_NONCE.nextPayload == ikev2_np_notify) {
        // Собираем из данных блок N1
        tempData += block_NONCE.length;
        tempLen -= block_NONCE.length;
        if (result = createBlockNotifyfromBuf(tempData, tempLen, &block_NOTIFY))
            return result;

        if (block_NOTIFY.notifyMessageType != NAT_DETECTION_SOURCE_IP) {
            return IKE_ERR_NOTIFY_MT;
        }

        //Расчет CRC32
        unsigned char *crcdata = (unsigned char *) malloc(24);
        memcpy(crcdata, (unsigned char *) &ikev2_sa->initSPI, 8);
        memcpy(crcdata + 8, (data - 20), 8);
        memcpy(crcdata + 16, (unsigned char *) &ikev2_sa->wanIpAdr, 4);
        memcpy(crcdata + 20, (unsigned char *) &ikev2_sa->wanPort, 2);
        crcdata[22] = 0;
        crcdata[23] = 0;

		unsigned int crc;
        //unsigned int crc = crc32(crcdata, 24);
        //if (memcmp(block_NOTIFY.Notify_Data, (unsigned char *) &crc, 4)) {
            // Нет проверки
        //}

        // Собираем из данных блок N2        tempData += block_NOTIFY.length;
        tempLen -= block_NOTIFY.length;
		tempData += block_NONCE.length;
		
        if (result = createBlockNotifyfromBuf(tempData, tempLen, &block_NOTIFY))
            return result;

        if (block_NOTIFY.notifyMessageType != NAT_DETECTION_DESTINATION_IP) {
            return IKE_ERR_NOTIFY_MT;
        }

        memcpy(crcdata + 16, (unsigned char *) &ikev2_sa->lanIpAdr, 4);
        memcpy(crcdata + 20, (unsigned char *) &ikev2_sa->lanPort, 2);
        crc = crc32(crcdata, 24);
        free(crcdata);
        if (memcmp(block_NOTIFY.Notify_Data, (unsigned char *) &crc, 4)) {
            ikev2_sa->haveNAT = 0;
        }
        else {
			ikev2_sa->haveNAT = 1;
        }
    }*/

	ikev2_sa->indexKeySA = indexKeySA;

	// Чтение ключа
    jclass clazz = (*ENV)->FindClass(ENV, "org/pniei/portal/vpn/VpnClient");
    jmethodID ins = (*ENV)->GetStaticMethodID(ENV, clazz, "ins", "()Lorg/pniei/portal/vpn/VpnClient;");
    jobject object = (*ENV)->CallStaticObjectMethod(ENV, clazz, ins);

	//jclass SIMDVS = (*ENV)->GetObjectClass(ENV,THIS);
	jmethodID getIndividKey = (*ENV)->GetMethodID(ENV, clazz, "getIndividKey","(S[B)Z");
	jbyteArray  buf = (*ENV)->NewByteArray(ENV, 32);
	jshort  numKey = ikev2_sa->indexKeySA;
	jboolean result2 = (*ENV)->CallBooleanMethod(ENV, object, getIndividKey, numKey, buf );

    if(!result2) {
        return IKE_ERR_CRIPT_KEY;
    }

	// Сохранение ключа
	uint8_t isCp;
	uint8_t * jkey = (uint8_t *)(*ENV)->GetByteArrayElements(ENV, buf, &isCp);
	memcpy(ikev2_sa->blockNote.key, jkey, 32);

	if(ikev2_sa->SecureIdentifyInf != NULL)
		free(ikev2_sa->SecureIdentifyInf);
	ikev2_sa->SecureIdentifyInf = (unsigned char *)malloc(264);

	unsigned char tz[64];
	int index = 0;
	for (int j = 0; j < 16; j++) {
		for (int i = 0; i < 8; i += 2) {
			tz[index] = ikev2_sa->blockNote.Table[i][j] | (ikev2_sa->blockNote.Table[i + 1][j] << 4);
			index++;
		}
	}

	init_updsch((unsigned char *)ikev2_sa->blockNote.key_dsh,
				(unsigned char *)ikev2_sa->blockNote.key,
				tz,
				ikev2_sa->SecureIdentifyInf,
				(unsigned char *)&(ikev2_sa->blockNote));

	if(ikev2_sa->nonceR != NULL) {
		free(ikev2_sa->nonceR);
		ikev2_sa->nonceR = NULL;
	}

	ikev2_sa->nonceR = (unsigned char *)malloc(block_NONCE.length - 4);
	memcpy(ikev2_sa->nonceR, block_NONCE.N_Data, block_NONCE.length - 4);
	ikev2_sa->stage = IKE_STAGE_2;

	// Выработка сеансовых ключей

	memcpy(temp, ikev2_sa->nonceI, 8);
	memcpy(temp+8, ikev2_sa->nonceR, 8);

	temp[16] = 1;
	memset(temp+17, 0 , 7);
    memset((unsigned char *)T, 0 , 32*4);

#if defined(CRYPT_GOST28147)
	GostStruct Cript;
	Cript.REGIM		= MAKE_IMZ;
	Cript.Key		= ikev2_sa->blockNote.key;
	Cript.LenIMZ	= LEN_IMZ_4;
	Cript.Din		= temp;
	Cript.Dout		= (unsigned char *)&T[0];
	Cript.LenBytes	= 24;
	Cript.TR_STATE	= TR_NO;
	Cript.Tz		= (unsigned char *)ikev2_sa->blockNote.Table;
	Gost28147(&Cript);
#elif defined(CRYPT_MAGMA)
	unsigned char imit_ctx[kImit89ContextLen];
	if(!cypher_magma_imit_init((unsigned char *)ikev2_sa->blockNote.key, LEN_IMZ_4, imit_ctx))
		return IKE_ERR_MAGMA_IMIT_INIT;
	if(!cypher_imit(imit_ctx, temp, (unsigned char *)&T[0], 24))
		return IKE_ERR_MAGMA_IMIT;
	free_imit(imit_ctx);
#else
	return IKE_ERR_CRYPT_ALG;
#endif

	for(int i = 1; i < 32; i++) {
		memcpy(temp  , (unsigned char *)&T[i-1], 4);
		memcpy(temp+4, ikev2_sa->nonceI, 8);
		memcpy(temp+12, ikev2_sa->nonceR, 8);
		temp[20] = i+1;
		memset(temp+21, 0 , 3);
#if defined(CRYPT_GOST28147)
		Cript.Din		= temp;
		Cript.Dout		= (unsigned char *)&T[i];
		Cript.LenBytes	= 24;
		Gost28147(&Cript);
#elif defined(CRYPT_MAGMA)
		if(!cypher_magma_imit_init((unsigned char *)ikev2_sa->blockNote.key, LEN_IMZ_4, imit_ctx))
			return IKE_ERR_MAGMA_IMIT_INIT;
		if(!cypher_imit(imit_ctx, temp, (unsigned char *)&T[i], 24))
			return IKE_ERR_MAGMA_IMIT;
		free_imit(imit_ctx);
#endif
	}

	memcpy((unsigned char *)&ikev2_sa->Kei, (unsigned char *)T, 32);
	memcpy((unsigned char *)&ikev2_sa->Ker, (unsigned char *)(T+8), 32);
	memcpy((unsigned char *)&ikev2_sa->Kai, (unsigned char *)(T+16), 32);
	memcpy((unsigned char *)&ikev2_sa->Kar, (unsigned char *)(T+24), 32);

	return IKE_OK;
}

unsigned int check_ike_sa_auth(unsigned char * data, int lenData, IKEv2_STRUCT_SA * ikev2_sa) {
	ikev2_block_SA block_SA;
	ikev2_block_SK block_SK;
	ikev2_block_AUTH block_AUTH;
    ikev2_block_IDENT block_IDENT;
	ikev2_block_TRAF_SELECTS block_TRAF_SELECTSi;
	ikev2_block_TRAF_SELECTS block_TRAF_SELECTSr;
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
	if(block_SK.nextPayload != ikev2_np_idr)
		return IKE_ERR_SK_NP;

#if defined(CRYPT_GOST28147)
	// Расшифрование
	GostStruct Cript;
	Cript.REGIM		= GAMMIROVANIE_OS_REG;
	Cript.CRYPT		= DECRYPT;
	Cript.Key		= ikev2_sa->Ker;
	Cript.Sp		= (unsigned int *)&block_SK.VI;
	Cript.Din		= block_SK.encrData;
	Cript.Dout		= block_SK.encrData;
	Cript.LenBytes	= block_SK.length - 28; //4 - заголовок, 8 - синхропосылка, 8 - изв, 8 - имитовставка
	Cript.TR_STATE	= TR_NO;
	Cript.Tz		= (unsigned char *)ikev2_sa->blockNote.Table;
	Gost28147(&Cript);

	// Расчет имитовставки
	Cript.REGIM		= MAKE_IMZ;
	Cript.Key		= ikev2_sa->Ker;
	Cript.LenIMZ	= LEN_IMZ_8;
	Cript.Din		= block_SK.encrData;
	Cript.Dout		= izv;
	Cript.LenBytes	= block_SK.length - 28;
	Cript.TR_STATE	= TR_NO;
	Cript.Tz		= (unsigned char *)ikev2_sa->blockNote.Table;
	Gost28147(&Cript);
#elif defined(CRYPT_MAGMA)
	unsigned char ctx[kCfb89ContextLen];
	if(!cypher_magma_cfb_init((unsigned char *)ikev2_sa->Ker, ctx, kBlockLen89, (unsigned char *)&block_SK.VI, 8))
		return IKE_ERR_MAGMA_CFB_INIT;

	int len_temp_buf = block_SK.length - 28;
	unsigned char * temp_buffer = (unsigned char * )malloc(len_temp_buf);
	if(!cypher_decr_cfb(ctx, block_SK.encrData, temp_buffer, len_temp_buf))
		return IKE_ERR_MAGMA_DECR;
	memcpy(block_SK.encrData, temp_buffer, len_temp_buf);
	free(temp_buffer);
	free_cfb(ctx);

	unsigned char imit_ctx[kImit89ContextLen];
	if(!cypher_magma_imit_init((unsigned char *)ikev2_sa->Ker, LEN_IMZ_8, imit_ctx))
		return IKE_ERR_MAGMA_IMIT_INIT;
	if(!cypher_imit(imit_ctx, block_SK.encrData, izv, block_SK.length - 28))
		return IKE_ERR_MAGMA_IMIT;
	free_imit(imit_ctx);
#endif
	if(memcmp(izv, data + (block_SK.length-8), 8)) {
		return IKE_ERR_IMZ_SK;
	}

	tempData = block_SK.encrData;
	tempLen = (block_SK.length - 28)			// Длина зашифрованных данных (и заполнения)
		- block_SK.encrData[block_SK.length-29] // Длина заполнения
		- 1;									// Длина поля "Длина заполнения"

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

	ikev2_sa->espRespSPI = block_SA.proposals[0].spi;

	//Расчет AUTHr
	memset(temp, 0 , 32);
	memcpy(temp  , ikev2_sa->initSPI, 8);
	memcpy(temp+8, ikev2_sa->respSPI, 8);
	memcpy(temp+16, (unsigned char *)&ikev2_sa->espRespSPI, 4);
	temp[20] = 5;

#if defined(CRYPT_GOST28147)
	Cript.REGIM		= MAKE_IMZ;
	Cript.Key		= ikev2_sa->Kar;
	Cript.LenIMZ	= LEN_IMZ_4;
	Cript.Din		= temp;
	Cript.Dout		= (unsigned char *)&A[0];
	Cript.LenBytes	= 24;
	Cript.TR_STATE	= TR_NO;
	Cript.Tz		= (unsigned char *)ikev2_sa->blockNote.Table;
	Gost28147(&Cript);
#elif defined(CRYPT_MAGMA)
	if(!cypher_magma_imit_init((unsigned char *)ikev2_sa->Kar, LEN_IMZ_4, imit_ctx))
		return IKE_ERR_MAGMA_IMIT_INIT;
	if(!cypher_imit(imit_ctx, temp, (unsigned char *)&A[0], 24))
		return IKE_ERR_MAGMA_IMIT;
	free_imit(imit_ctx);
#endif

	memcpy(temp+4, ikev2_sa->initSPI, 8);
	memcpy(temp+12, ikev2_sa->respSPI, 8);
	memcpy(temp+20, (unsigned char *)&ikev2_sa->espRespSPI, 4);

	for(int i = 1; i < 4; i++) {
		memcpy(temp  , (unsigned char *)&A[i-1], 4);
		temp[24] = i+5;
#if defined(CRYPT_GOST28147)
		Cript.Din		= temp;
		Cript.Dout		= (unsigned char *)&A[i];
		Cript.LenBytes	= 32;
		Cript.TR_STATE	= TR_NO;
		Gost28147(&Cript);
#elif defined(CRYPT_MAGMA)
		if(!cypher_magma_imit_init((unsigned char *)ikev2_sa->Kar, LEN_IMZ_4, imit_ctx))
			return IKE_ERR_MAGMA_IMIT_INIT;
		if(!cypher_imit(imit_ctx, temp, (unsigned char *)&A[i], 32))
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
	if(block_SA.nextPayload == ikev2_np_TSi) {
		tempData += block_SA.length;
		tempLen  -= block_SA.length;
		if(result = createBlockTRAFSELECTSfromBuf(tempData, tempLen, &block_TRAF_SELECTSi))
			return result;

		ikev2_sa->numSTi = block_TRAF_SELECTSi.numOfTSs;
		ikev2_sa->TSi = (TRAF_SELECT *)malloc(sizeof(TRAF_SELECT) * ikev2_sa->numSTi);
        for(int i = 0; i < ikev2_sa->numSTi; i++) {
            ikev2_sa->TSi[i].startPort = block_TRAF_SELECTSi.ID_Data[i].start_port;
            ikev2_sa->TSi[i].endPort = block_TRAF_SELECTSi.ID_Data[i].end_port;
            ikev2_sa->TSi[i].startAdd = block_TRAF_SELECTSi.ID_Data[i].start_address;
            ikev2_sa->TSi[i].endAdd = block_TRAF_SELECTSi.ID_Data[i].end_address;
        }

        if(block_TRAF_SELECTSi.nextPayload == ikev2_np_TSr) {
            tempData += block_TRAF_SELECTSi.length;
            tempLen  -= block_TRAF_SELECTSi.length;
            if(result = createBlockTRAFSELECTSfromBuf(tempData, tempLen, &block_TRAF_SELECTSr))
                return result;

            ikev2_sa->numSTr = block_TRAF_SELECTSr.numOfTSs;
            ikev2_sa->TSr = (TRAF_SELECT *)malloc(sizeof(TRAF_SELECT) * ikev2_sa->numSTr);
            for(int i = 0; i < ikev2_sa->numSTr; i++) {
                ikev2_sa->TSr[i].startPort = block_TRAF_SELECTSr.ID_Data[i].start_port;
                ikev2_sa->TSr[i].endPort = block_TRAF_SELECTSr.ID_Data[i].end_port;
                ikev2_sa->TSr[i].startAdd = block_TRAF_SELECTSr.ID_Data[i].start_address;
                ikev2_sa->TSr[i].endAdd = block_TRAF_SELECTSr.ID_Data[i].end_address;
            }
        }
	}

    ikev2_sa->IP_addr = ikev2_sa->TSi[0].startAdd;
	int m = 0, n = 32;
	unsigned int razn = ikev2_sa->TSr[0].endAdd - ikev2_sa->TSr[0].startAdd;
	while(n) {
		if(razn != 0)
			m++;
		else
			break;
		razn = razn >> 1;
		n--;
	}
    ikev2_sa->IP_mask 		= 32 - m;
	ikev2_sa->stage			= IKE_STAGE_4;
	ikev2_sa->inMessageID	= 2;
	ikev2_sa->outMessageID	= 2;
	ikev2_sa->inSNESP		= 0;
	ikev2_sa->outSNESP		= 0;

	for(int i = 0; i < 2; i++) {
		if(ikev2_sa_pull[i].ikev2_sa == ikev2_sa) {
			index_main_ikev2_sa = i;
			break;
		}
	}

	return IKE_OK;
}

unsigned int checkSavedProposals(ikev2_block_SA * block_SA) {
	// Заглушка
	return IKE_OK;
}