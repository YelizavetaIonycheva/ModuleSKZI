
#include <stdlib.h>
#include <string.h>

#include "updsch_manager.h"
#include "ESP.h"
#include "IKEv2.h"
#include "MMT.h"
#include "F.h"
#if defined(CRYPT_GOST28147)
    #include "Gost28147.h"
#elif defined(CRYPT_MAGMA)
    #include "cypher.h"
#endif

int esp_processing_data(unsigned char * dataIn, int lenDataIn, unsigned char ** dataOut, int * lenDataOut) {
    IKEv2_STRUCT_SA *_ikev2_sa = NULL;
    ESP_PACKET block_ESP;
    int tempLen;
    int result;
    unsigned char *tempData = dataIn;
    unsigned char izv[LEN_IMZ_8];

    tempLen = lenDataIn;

    // Собираем из данных структуру ESP_PACKET
    if (result = createBlockESPfromBuf(tempData, tempLen, &block_ESP)) {
        return result;
    }

    for (int i = 0; i < 2; i++) {
        if (ikev2_sa_pull[i].ikev2_sa != NULL) {
            if (block_ESP.SPI == ikev2_sa_pull[i].ikev2_sa->espRespSPI) {
                _ikev2_sa = ikev2_sa_pull[i].ikev2_sa;
                break;
            }
        }
    }

    if (_ikev2_sa == NULL || _ikev2_sa->stage != IKE_STAGE_4) {
        return IKE_ERR_STAGE;
    }

    // Проверяем имитовставку на заголовок
    // Расчет ИЗВ на заголовки
#if defined(CRYPT_GOST28147)
    GostStruct Cript;
    Cript.REGIM		= MAKE_IMZ;
    Cript.Key       = _ikev2_sa->role ? _ikev2_sa->Kar : _ikev2_sa->Kai;
    /*if(_ikev2_sa->role == IKE_INITIATOR)
        Cript.Key		= _ikev2_sa->Kar;
    else
        Cript.Key		= _ikev2_sa->Kai;*/
    Cript.Din		= dataIn;
    Cript.LenIMZ	= LEN_IMZ_8;
    Cript.Dout		= izv;
    Cript.LenBytes	= ikev2_SIZE_ESP_H_TO_IMZ;
    Cript.TR_STATE	= TR_NO;
    Cript.Tz		= (unsigned char *)_ikev2_sa->blockNote.Table;
    Gost28147(&Cript);
#elif defined(CRYPT_MAGMA)
    unsigned char imit_ctx[kImit89ContextLen];
    if (!cypher_magma_imit_init((unsigned char *) _ikev2_sa->role ? _ikev2_sa->Kar : _ikev2_sa->Kai, LEN_IMZ_8, imit_ctx)) {
        return IKE_ERR_MAGMA_IMIT_INIT;
    }
    if (!cypher_imit(imit_ctx, dataIn, izv, ikev2_SIZE_ESP_H_TO_IMZ)) {
        return IKE_ERR_MAGMA_IMIT;
    }
    free_imit(imit_ctx);
#endif

	if(memcmp(izv, block_ESP.IZV, 8)){
		return IKE_ERR_IMZ_ESP_HDR;
	}

    if(_ikev2_sa->inSNESP > block_ESP.SN) {
        if ((_ikev2_sa->inSNESP - block_ESP.SN) > ikev2_SIZE_ESP_SN_WINDOW) {
            return IKE_ERR_SN_OVER;
        }
    }
	tempLen = lenDataIn - ikev2_SIZE_ESP_H; //Длина зашифрованных данных
	
	if((tempLen % SIZE_CRYPT_BLOCK) != 0) {
		return IKE_ERR_LEN;
	}
	// Расчет пакетного ключа
	if(_ikev2_sa->role == IKE_INITIATOR)
		get_packet_key(_ikev2_sa->Ker, dataIn + 8, _ikev2_sa->Kpacket);
	else
		get_packet_key(_ikev2_sa->Kei, dataIn + 8, _ikev2_sa->Kpacket);

#if defined(CRYPT_GOST28147)
	// Расшифрование
	Cript.REGIM		= GAMMIROVANIE_OS_REG;
	Cript.CRYPT		= DECRYPT;
	Cript.Key		= _ikev2_sa->Kpacket;
	Cript.Sp		= (unsigned int *)(dataIn + 8);
	Cript.Din		= block_ESP.encrData;
    Cript.Dout		= block_ESP.encrData;
	Cript.LenBytes 	= tempLen;
	Cript.TR_STATE 	= TR_NO;
	Cript.Tz		= (unsigned char *)_ikev2_sa->blockNote.Table;
	Gost28147(&Cript);

	// Расчет имитовставки
	Cript.REGIM		= MAKE_IMZ;
	Cript.Key		= _ikev2_sa->Kpacket;
	Cript.LenIMZ	= LEN_IMZ_8;
	Cript.Din		= block_ESP.encrData;
	Cript.Dout		= izv;
	Cript.LenBytes	= tempLen; 
	Cript.TR_STATE	= TR_NO;
	Cript.Tz		= (unsigned char *)_ikev2_sa->blockNote.Table;
	Gost28147(&Cript);
#elif defined(CRYPT_MAGMA)
	unsigned char ctx[kCfb89ContextLen];
	if(!cypher_magma_cfb_init((unsigned char *)_ikev2_sa->Kpacket, ctx, kBlockLen89, dataIn + 8, 8)) {
        return IKE_ERR_MAGMA_CFB_INIT;
    }
	int len_temp_buf = tempLen;
	unsigned char * temp_buffer = (unsigned char * )malloc(len_temp_buf);
	if(!cypher_decr_cfb(ctx, block_ESP.encrData, temp_buffer, len_temp_buf)) {
        return IKE_ERR_MAGMA_DECR;
    }
	memcpy(block_ESP.encrData, temp_buffer, len_temp_buf);
	free(temp_buffer);
	free_cfb(ctx);

	if(!cypher_magma_imit_init((unsigned char *)_ikev2_sa->Kpacket, LEN_IMZ_8, imit_ctx)) {
        return IKE_ERR_MAGMA_IMIT_INIT;
    }
	if(!cypher_imit(imit_ctx, block_ESP.encrData, izv, tempLen)) {
        return IKE_ERR_MAGMA_IMIT;
    }

	free_imit(imit_ctx);
#endif
	if(memcmp(izv, dataIn + (lenDataIn-LEN_IMZ_8), 8)){
		return IKE_ERR_IMZ_ESP_DATA;
	}

	block_ESP.nextH	 = *(block_ESP.encrData + (tempLen - 1));
	block_ESP.padLen = *(block_ESP.encrData + (tempLen - 2));

	//Пока что обработка только IP-пакетов
	if(block_ESP.nextH != IPV4) {
		return IKE_ERR_SUPPORT_ONLY_IPV4;
	}

	*lenDataOut = tempLen - 2 - block_ESP.padLen;  //Длина открытых данных

    if(block_ESP.SN > _ikev2_sa->inSNESP) {
        _ikev2_sa->inSNESP = block_ESP.SN;
    }

    _ikev2_sa->inSNESP++;
	*dataOut = block_ESP.encrData;
	return IKE_SEND;
}

int createBlockESPfromBuf(unsigned char * data, int lenData, ESP_PACKET * block_ESP) {
    block_ESP->SPI		= *(unsigned int*)data;
    block_ESP->SN		= *(unsigned int*)(data + 4);
    memcpy(block_ESP->VI, data + 8, 8);
	memcpy(block_ESP->IZV, data + 16, 8);
    block_ESP->encrData	= data + 24;
	memcpy(block_ESP->IMZ, data + lenData - 8, 8);
	return IKE_OK;
}

int esp_encapsul_data( unsigned char * dataIn, int lenDataIn, unsigned char ** dataOut, int * lenDataOut) {
	unsigned short lenPayloadData;	    // Размер данных для инкапсуляции в ESP
	unsigned char * ikev2_buf;		    // Результат инкапсуляции
	unsigned char lenPadding;		    // Размер заполнения в байтах
	unsigned char izv[8];			    // Для хранения имитовставки
	unsigned char sizeBlockCripto = 8;	// Размер блока шифрования 8 байт (64 бита)
	unsigned char lenPadLength	= 1;	// Размер блока "PadLen" в байтах
	unsigned char lenNextHeader = 1;	// Размер блока "Next Header" в байтах
	int result;
	*lenDataOut = 0;

	IKEv2_STRUCT_SA * ikev2_sa = ikev2_sa_pull[index_main_ikev2_sa].ikev2_sa;

	// Проверка контекста безопаности
	if(result = check_ikesa_stage(ikev2_sa)) {
		return result;
	}

#ifndef NO_TSI
	// Проверка селектора трафика
	if(result = check_tsi_tsr(IPV4, dataIn, ikev2_sa)) {
		return result;
	}
#endif

	//Подсчет длины всего сообщения ESP
	lenPayloadData = lenDataIn;
	lenPadding = (sizeBlockCripto -  (lenPayloadData + lenPadLength + lenNextHeader) % sizeBlockCripto);

	*lenDataOut = ikev2_SIZE_ESP_H +
			   lenPayloadData +
			   lenPadding + 
			   lenPadLength +
			   lenNextHeader;
	
	ikev2_buf = (unsigned char *)malloc(*lenDataOut);

	*(unsigned int *)ikev2_buf				= ikev2_sa->espInitSPI;		// SPI
	*(unsigned int *)(ikev2_buf + 4)		= ikev2_sa->outSNESP;		// SeqNumber
	ikev2_sa->outSNESP++;
	//*(unsigned int *)(ikev2_buf + 8)		= random();				//Initialization Vector
    //*(unsigned int *)(ikev2_buf + 12)		= random();				//Initialization Vector
	memcpy(ikev2_buf + 8, get_random(ikev2_sa->SecureIdentifyInf), 8);

	// Расчет ИЗВ на заголовки
#if defined(CRYPT_GOST28147)
	GostStruct Cript;
	Cript.REGIM		= MAKE_IMZ;
	Cript.Key		= ikev2_sa->Kai;
	Cript.Din		= ikev2_buf;
	Cript.LenIMZ	= LEN_IMZ_8;
	Cript.Dout		= izv;
	Cript.LenBytes	= ikev2_SIZE_ESP_H_TO_IMZ;
	Cript.TR_STATE	= TR_NO;
	Cript.Tz		= (unsigned char *)ikev2_sa->blockNote.Table;
	Gost28147(&Cript);
#elif defined(CRYPT_MAGMA)
	unsigned char imit_ctx[kImit89ContextLen];
	if(!cypher_magma_imit_init((unsigned char *)ikev2_sa->Kai, LEN_IMZ_8, imit_ctx))
		return IKE_ERR_MAGMA_IMIT_INIT;
	if(!cypher_imit(imit_ctx, ikev2_buf, izv, ikev2_SIZE_ESP_H_TO_IMZ))
		return IKE_ERR_MAGMA_IMIT;
	free_imit(imit_ctx);
#endif

	memcpy((ikev2_buf + 16), izv, LEN_IMZ_8);			// Копируем ИЗВ
	memcpy((ikev2_buf + 24), dataIn, lenDataIn);		// Копируем данные для инкапсуляции

	for(int i = 1; i <= lenPadding; i++) {
		ikev2_buf[*lenDataOut - 10 - (lenPadding + 1 - i)] = i;
	}

	*(ikev2_buf + ((*lenDataOut) - 10)) = lenPadding;	// Pad Length
	*(ikev2_buf + ((*lenDataOut) - 9))  = dataIn[0] >> 4;
	//*(ikev2_buf + ((*lenDataOut) - 9))  = IPV4;		// Hext Header

	// Расчет пакетного ключа
	get_packet_key(ikev2_sa->Kei, ikev2_buf + 8, ikev2_sa->Kpacket);

#if defined(CRYPT_GOST28147)
	// Расчет имитовставки
	Cript.REGIM		= MAKE_IMZ;
	Cript.Key		= ikev2_sa->Kpacket;
	Cript.LenIMZ	= LEN_IMZ_8;
	Cript.Din		= (ikev2_buf + ikev2_SIZE_ESP_H_TO_IMZ + LEN_IMZ_8);
	Cript.Dout		= ikev2_buf + (*lenDataOut - LEN_IMZ_8);
	Cript.LenBytes	= lenPadding + lenPayloadData + lenPadLength + lenNextHeader;
	Cript.TR_STATE	= TR_NO;
	Cript.Tz		= (unsigned char *)ikev2_sa->blockNote.Table;
	Gost28147(&Cript);

	// Шифрование
	Cript.REGIM	= GAMMIROVANIE_OS_REG;
	Cript.CRYPT	= ENCRYPT;
	Cript.Key	= ikev2_sa->Kpacket;
	Cript.Sp	= (unsigned int *)(ikev2_buf + 8);
	Cript.Din	= ikev2_buf + 24;
	Cript.Dout	= ikev2_buf + 24;
	Cript.LenBytes = lenPadding + lenPayloadData + lenPadLength + lenNextHeader;
	Cript.TR_STATE = 0;
	Cript.Tz		= (unsigned char *)ikev2_sa->blockNote.Table;
	Gost28147(&Cript);
#elif defined(CRYPT_MAGMA)
	if(!cypher_magma_imit_init((unsigned char *)ikev2_sa->Kpacket, LEN_IMZ_8, imit_ctx))
		return IKE_ERR_MAGMA_IMIT_INIT;
	if(!cypher_imit(imit_ctx,(ikev2_buf + ikev2_SIZE_ESP_H_TO_IMZ + LEN_IMZ_8), ikev2_buf + (*lenDataOut - LEN_IMZ_8), lenPadding + lenPayloadData + lenPadLength + lenNextHeader))
		return IKE_ERR_MAGMA_IMIT;
	free_imit(imit_ctx);

	unsigned char ctx[kCfb89ContextLen];
	if(!cypher_magma_cfb_init((unsigned char *)ikev2_sa->Kpacket, ctx, kBlockLen89, ikev2_buf + 8, 8))
		return IKE_ERR_MAGMA_CFB_INIT;
	int len_temp_buf = lenPadding + lenPayloadData + lenPadLength + lenNextHeader;
	unsigned char * temp_buffer = (unsigned char * )malloc(len_temp_buf);
	if(!cypher_encr_cfb(ctx, ikev2_buf + 24, temp_buffer, len_temp_buf))
		return IKE_ERR_MAGMA_CRPT;
	memcpy(ikev2_buf + 24, temp_buffer, len_temp_buf);
	free(temp_buffer);
	free_cfb(ctx);
#endif

	*dataOut = ikev2_buf;
	return 0;
}

int esp_mmt_encapsul_data(IKEv2_STRUCT_SA * ikev2_sa_a, unsigned char * dataIn, int lenDataIn, unsigned char ** dataOut, int * lenDataOut, unsigned char protocol) {
	unsigned short lenPayloadData;	    // Размер данных для инкапсуляции в ESP
	unsigned char * ikev2_buf;		    // Результат инкапсуляции
	unsigned char lenPadding;		    // Размер заполнения в байтах
	unsigned char izv[8];			    // Для хранения имитовставки
	unsigned char sizeBlockCripto = 8;	// Размер блока шифрования 8 байт (64 бита)
	unsigned char lenPadLength	= 1;	// Размер блока "PadLen" в байтах
	unsigned char lenNextHeader = 1;	// Размер блока "Next Header" в байтах

	// Проверка контекста безопаности
	if(ikev2_sa_a == NULL || ikev2_sa_a->stage != IKE_STAGE_4) {
		return IKE_ERR_STAGE;
	}

	//Подсчет длины всего сообщения ESP
	lenPayloadData = lenDataIn;
	lenPadding = (sizeBlockCripto -  (lenPayloadData + lenPadLength + lenNextHeader) % sizeBlockCripto);

	*lenDataOut = ikev2_SIZE_ESP_H +
				  lenPayloadData +
				  lenPadding +
				  lenPadLength +
				  lenNextHeader;

	ikev2_buf = (unsigned char *)malloc(*lenDataOut);

    *(unsigned int *)ikev2_buf = ikev2_sa_a->role ? ikev2_sa_a->espInitSPI : ikev2_sa_a->espRespSPI;

	*(unsigned int *)(ikev2_buf + 4)		= ikev2_sa_a->outSNESP;			// SeqNumber
	ikev2_sa_a->outSNESP++;	//Возможно стоит увеличивать после отправки, здесь рано !!!!!!!!!!!!!!!!!!!!!!!!!!!!
	
	//*(unsigned int *)(ikev2_buf + 8)		= random();				//Initialization Vector
    //*(unsigned int *)(ikev2_buf + 12)		= random();				//Initialization Vector
	memcpy(ikev2_buf + 8, get_random(ikev2_sa_a->SecureIdentifyInf), 8);

	// Расчет ИЗВ на заголовки
#if defined(CRYPT_GOST28147)
	GostStruct Cript;
	Cript.REGIM		= MAKE_IMZ;
	Cript.Key       = ikev2_sa_a->role ? ikev2_sa_a->Kai : ikev2_sa_a->Kar;

	/*if(ikev2_sa_a->role == IKE_INITIATOR)
		Cript.Key		= ikev2_sa_a->Kai;
	else
		Cript.Key		= ikev2_sa_a->Kar;*/
	Cript.Din		= ikev2_buf;
	Cript.LenIMZ	= LEN_IMZ_8;
	Cript.Dout		= izv;
	Cript.LenBytes	= ikev2_SIZE_ESP_H_TO_IMZ;
	Cript.TR_STATE	= TR_NO;
	Cript.Tz		= (unsigned char *)ikev2_sa_a->blockNote.Table;
	Gost28147(&Cript);
#elif defined(CRYPT_MAGMA)
	unsigned char imit_ctx[kImit89ContextLen];
    if (!cypher_magma_imit_init((unsigned char *) ikev2_sa_a->role ? ikev2_sa_a->Kai : ikev2_sa_a->Kar, LEN_IMZ_8, imit_ctx))
        return IKE_ERR_MAGMA_IMIT_INIT;
	if(!cypher_imit(imit_ctx, ikev2_buf, izv, ikev2_SIZE_ESP_H_TO_IMZ))
		return IKE_ERR_MAGMA_IMIT;
	free_imit(imit_ctx);
#endif

	memcpy((ikev2_buf + 16), izv, LEN_IMZ_8);			// Копируем ИЗВ
	memcpy((ikev2_buf + 24), dataIn, lenDataIn);	    // Копируем данные для инкапсуляции

	for(int i = 1; i <= lenPadding; i++) {
		ikev2_buf[*lenDataOut - 10 - (lenPadding + 1 - i)] = i;
	}

	*(ikev2_buf + ((*lenDataOut) - 10)) = lenPadding;	// Pad Length
	*(ikev2_buf + ((*lenDataOut) - 9))  = protocol;		// Hext Header

	// Расчет пакетного ключа
	if(ikev2_sa_a->role == IKE_INITIATOR)
		get_packet_key(ikev2_sa_a->Kei, ikev2_buf + 8, ikev2_sa_a->Kpacket);
	else
		get_packet_key(ikev2_sa_a->Ker, ikev2_buf + 8, ikev2_sa_a->Kpacket);

#if defined(CRYPT_GOST28147)
	// Расчет имитовставки
	Cript.REGIM		= MAKE_IMZ;
	Cript.Key		= ikev2_sa_a->Kpacket;
	Cript.LenIMZ	= LEN_IMZ_8;
	Cript.Din		= ikev2_buf + ikev2_SIZE_ESP_H_TO_IMZ + LEN_IMZ_8;
	Cript.Dout		= ikev2_buf + (*lenDataOut - LEN_IMZ_8);
	Cript.LenBytes	= lenPadding + lenPayloadData + lenPadLength + lenNextHeader;
	Cript.TR_STATE	= TR_NO;
	Cript.Tz		= (unsigned char *)ikev2_sa_a->blockNote.Table;
	Gost28147(&Cript);

	// Шифрование
	Cript.REGIM	= GAMMIROVANIE_OS_REG;
	Cript.CRYPT	= ENCRYPT;
	Cript.Key	= ikev2_sa_a->Kpacket;
	Cript.Sp	= (unsigned int *)(ikev2_buf + 8);
	Cript.Din	= ikev2_buf + 24;
	Cript.Dout	= ikev2_buf + 24;
	Cript.LenBytes 	= lenPadding + lenPayloadData + lenPadLength + lenNextHeader;
	Cript.TR_STATE 	= 0;
	Cript.Tz		= (unsigned char *)ikev2_sa_a->blockNote.Table;
	Gost28147(&Cript);
#elif defined(CRYPT_MAGMA)
	if(!cypher_magma_imit_init((unsigned char *)ikev2_sa_a->Kpacket, LEN_IMZ_8, imit_ctx))
		return IKE_ERR_MAGMA_IMIT_INIT;
	if(!cypher_imit(imit_ctx, ikev2_buf + ikev2_SIZE_ESP_H_TO_IMZ + LEN_IMZ_8, ikev2_buf + (*lenDataOut - LEN_IMZ_8), lenPadding + lenPayloadData + lenPadLength + lenNextHeader))
		return IKE_ERR_MAGMA_IMIT;
	free_imit(imit_ctx);

	unsigned char ctx[kCfb89ContextLen];
	if(!cypher_magma_cfb_init((unsigned char *)ikev2_sa_a->Kpacket, ctx, kBlockLen89, ikev2_buf + 8, 8))
		return IKE_ERR_MAGMA_CFB_INIT;
	int len_temp_buf = lenPadding + lenPayloadData + lenPadLength + lenNextHeader;
	unsigned char * temp_buffer = (unsigned char * )malloc(len_temp_buf);
	if(!cypher_encr_cfb(ctx, ikev2_buf + 24, temp_buffer, len_temp_buf))
		return IKE_ERR_MAGMA_CRPT;
	memcpy(ikev2_buf + 24, temp_buffer, len_temp_buf);
	free(temp_buffer);
	free_cfb(ctx);
#endif
	memset(ikev2_sa_a->Kpacket, 0, SIZE_KEY);

	*dataOut = ikev2_buf;
	return 0;
}
