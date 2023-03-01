#include <stdlib.h>
#include <string.h>
#include <crc32.h>

#include "CryptUtils.h"
#include "Hesh341112.h"
#include "updsch_manager.h"

/*#if defined(CRYPT_GOST28147)
#include "Gost28147.h"
#elif defined(CRYPT_MAGMA)*/
#include "cypher.h"
#include "cypher_magma.h"
//#endif

static unsigned char KEY_CRYPT_SOUND_OUT[SIZE_KEY];
static unsigned char KEY_CRYPT_SOUND_IN[SIZE_KEY];
static unsigned char IS_CRYPT = 0;
static unsigned char ctx_file_crypt[kCtr89ContextLen];
static unsigned char ctx_file_imit[kImit89ContextLen];
static unsigned char IZV[LEN_IMZ_4];
static unsigned char KEY_BLOCK[SIZE_KEY];
static unsigned char * SecureIdentifyInf_PP = NULL;


void init_key_block(unsigned char * key, unsigned int len_key) {
    if (key != NULL) {
        if (len_key > SIZE_KEY)
            len_key = SIZE_KEY;
        memcpy(KEY_BLOCK, key, len_key);
    }
}

/**
 * Функция шифрования блока данных
 * @param is_first 	- признак первого блока данных
 * @param data 		- данные для шифрования
 * @param len_data 	- размер data
 * @param sp  		- синхропосылка
 * @return 			- зашифрованные данные
 */
unsigned char * crypt_data_block(int is_first, unsigned char *data, int len_data, unsigned char *sp) {
    unsigned char * crypted_data = NULL;
    unsigned char * key = NULL;
    unsigned int num0 = 0;
    unsigned char * buffer = NULL;

    if (data == NULL || len_data == 0)
        return NULL;

    if(is_first == 1) {
        key = KEY_BLOCK;
        if(sp == NULL)
            return NULL;
        free_cfb(ctx_file_crypt);
        if(!cypher_magma_cfb_init(key, ctx_file_crypt, kBlockLen89, sp, 8))
            goto error;
        free_imit(ctx_file_imit);
        if (!cypher_magma_imit_init(key, LEN_IMZ_4, ctx_file_imit))
            goto error;
        memset(IZV, 0, LEN_IMZ_4);
    }

    crypted_data = (unsigned char *)malloc(len_data);
    if(crypted_data == NULL)
        goto error;

    if (len_data % 8 != 0) {
        //num0 = ((len_data / 8 + 1) * 8) - len_data;
        num0 = 8 - (len_data & 7);
    }
    if(num0 == 0) {
        buffer = data;
    } else {
        buffer = (unsigned char *) malloc(len_data + num0);
        memcpy(buffer, data, len_data);
        memset(buffer + len_data, 0, num0);
    }

#if defined(CRYPT_GOST28147)
    // Шифрование Не переделано
    GostStruct Cript;
	Cript.REGIM	= GAMMIROVANIE_OS_REG;
	Cript.CRYPT	= ENCRYPT;
	Cript.Key	= key;
	Cript.Sp	= (unsigned int *)sp;
	Cript.Din	= data;
	Cript.Dout	= crypted_data+8;
	Cript.LenBytes = len_data;
	Cript.TR_STATE = TR_NO;
	Cript.Tz	= (unsigned char *)TABLE;
	Gost28147(&Cript);
#elif defined(CRYPT_MAGMA)
    if(!cypher_imit(ctx_file_imit, buffer, IZV, len_data + num0))
        goto error;
    if(!cypher_encr_cfb(ctx_file_crypt, buffer, crypted_data, len_data))
        goto error;
#endif
    if(key == NULL) {
        free(key);
    }
    if(num0 != 0) {
        free(buffer);
    }
    return crypted_data;

    error:
    if(key == NULL) {
        free(key);
    }
    if(crypted_data != NULL) {
        free(crypted_data);
    }
    if(buffer != NULL && num0 != 0) {
        free(buffer);
    }
    return NULL;
}

/**
 * Функция расшифрования блока данных
 * @param is_first 	- признак первого блока данных
 * @param data 		- данные для расшифрования
 * @param len_data 	- размер data
 * @param key 		- ключ шифрования
 * @param sp  		- синхропосылка
 * @return 			- расшифрованные данные
 */
unsigned char * decrypt_data_block(int is_first, unsigned char *data, int len_data, unsigned char *sp)  {
    unsigned char * decrypted_data = NULL;
    unsigned char * key = NULL;
    unsigned char * buffer = NULL;
    unsigned int num0 = 0;

    if (data == NULL || len_data == 0)
        return NULL;

    if(is_first == 1) {
        key = KEY_BLOCK;
        if(sp == NULL)
            return NULL;
        free_cfb(ctx_file_crypt);
        if(!cypher_magma_cfb_init(key, ctx_file_crypt, kBlockLen89, sp, 8))
            goto error;
        free_imit(ctx_file_imit);
        if (!cypher_magma_imit_init(key, LEN_IMZ_4, ctx_file_imit))
            goto error;
        memset(IZV, 0, LEN_IMZ_4);
    }

    decrypted_data = (unsigned char *)malloc(len_data);
    if(decrypted_data == NULL)
        goto error;

#if defined(CRYPT_GOST28147)
    // Шифрование Не переделано
    GostStruct Cript;
	Cript.REGIM	= GAMMIROVANIE_OS_REG;
	Cript.CRYPT	= ENCRYPT;
	Cript.Key	= key;
	Cript.Sp	= (unsigned int *)sp;
	Cript.Din	= data;
	Cript.Dout	= decrypted_data+8;
	Cript.LenBytes = len_data;
	Cript.TR_STATE = TR_NO;
	Cript.Tz	= (unsigned char *)TABLE;
	Gost28147(&Cript);
#elif defined(CRYPT_MAGMA)
    if(!cypher_decr_cfb(ctx_file_crypt, data, decrypted_data, len_data))
        goto error;

    if (len_data % 8 != 0) {
        //num0 = ((len_data / 8 + 1) * 8) - len_data;
        num0 = 8 - (len_data & 7);
    }

    if(num0 == 0) {
        buffer = decrypted_data;
    } else {
        buffer = (unsigned char *) malloc(len_data + num0);
        memcpy(buffer, decrypted_data, len_data);
        memset(buffer+len_data, 0, num0);
    }

    if(!cypher_imit(ctx_file_imit, buffer, IZV, len_data + num0))
        goto error;
#endif
    if(key == NULL) {
        free(key);
    }
    if(num0 != 0) {
        free(buffer);
    }
    return decrypted_data;

    error:
    if(key == NULL) {
        free(key);
    }
    if(decrypted_data != NULL) {
        free(decrypted_data);
    }
    if(num0 != 0 && buffer != NULL) {
        free(buffer);
    }
    return NULL;
}

unsigned char * getIZV() {
    return IZV;
}

/**
 * Функция установки ключа для шифрования пакетов RTP
 * @param key
 * @param isCript
 * @param randomC
 */
void init_crypt_sound(unsigned char * key_out, unsigned char * key_in, unsigned char isCript) {
	IS_CRYPT = isCript;
    if(isCript == 1) {
        memcpy(KEY_CRYPT_SOUND_OUT, key_out, SIZE_KEY);
        memcpy(KEY_CRYPT_SOUND_IN, key_in, SIZE_KEY);
    } else {
        memset(KEY_CRYPT_SOUND_OUT, 0, SIZE_KEY);
        memset(KEY_CRYPT_SOUND_IN, 0, SIZE_KEY);
    }
}

unsigned char * crypt_sound(unsigned char * data, int len_data, int * len_close_data) {
	if (IS_CRYPT == 0) {
		*len_close_data = 0;
		return NULL;
	} else {
		return crypt(data, len_data, KEY_CRYPT_SOUND_OUT, SIZE_KEY, len_close_data);
	}
}

unsigned char * decrypt_sound(unsigned char * data, int len_data, int * len_open_data) {
	if (IS_CRYPT == 0) {
		*len_open_data = 0;
		return NULL;
	} else {
		return decrypt(data, len_data, KEY_CRYPT_SOUND_IN, SIZE_KEY, len_open_data);
	}
}

/**
 * Функция расшифрования данных
 * @param crypted_data  		- зашифрованные данные в формате |синхропосылка (8 байт)|зашифрованные данные|имитозащита (8 байт)|
 * @param len_crypted_data 		- размер зашифрованных данных
 * @param key 					- ключ
 * @param len_key 				- размер key
 * @param len_open_data 		- размер расшифрованных данных
 * @return 						- расшифрованные данные
 */
unsigned char * decrypt_data(unsigned char * crypted_data, int len_crypted_data, unsigned char * key, int len_key, int * len_open_data) {
    unsigned char ctx[kCfb89ContextLen];
    unsigned char imit_ctx[kImit89ContextLen];
    unsigned char * open_data = NULL;
    unsigned char * sp;
    unsigned char * buffer = NULL;
    unsigned char imz[LEN_IMZ_8];
    unsigned int num0 = 0;

	if(crypted_data == NULL || len_crypted_data < (LEN_SP_8 + LEN_IMZ_8 + 1) || key == NULL)
		goto error;

    *len_open_data = len_crypted_data - LEN_SP_8 - LEN_IMZ_8;

    open_data = (unsigned char *)malloc(*len_open_data);
    if(open_data == NULL)
        goto error;

    sp = crypted_data;
    if(!cypher_magma_cfb_init(key, ctx, kBlockLen89, sp, LEN_SP_8))
        goto error;
    if(!cypher_decr_cfb(ctx, crypted_data + LEN_SP_8, open_data, *len_open_data))
        goto error;
    free_cfb(ctx);

    if (*len_open_data % 8 != 0) {
        // = ((*len_open_data / 8 + 1) * 8) - *len_open_data;
        num0 = 8 - (*len_open_data & 7);
    }

    if(num0 == 0) {
        buffer = open_data;
    } else {
        buffer = (unsigned char *) malloc((*len_open_data) + num0);
        memcpy(buffer, open_data, (*len_open_data));
        memset(buffer + (*len_open_data), 0, num0);
    }

    if(!cypher_magma_imit_init((unsigned char *)key, LEN_IMZ_8, imit_ctx))
        goto error;
    if(!cypher_imit(imit_ctx, buffer, imz, (*len_open_data) + num0))
        goto error;
    free_imit(imit_ctx);
    if (num0 > 0)
        free(buffer);

    if(*(unsigned int*)(crypted_data + LEN_SP_8 + (*len_open_data)) != *(unsigned int*)imz) {
        goto error;
    }

    return open_data;

error:
    if (num0 > 0)
        free(buffer);
    if(open_data != NULL)
        free(open_data);
    (*len_open_data) = 0;
    return NULL;
}

static unsigned char * getSP(int len_sp) {
	unsigned char * buff = (unsigned char *)malloc(len_sp);
	if(buff == NULL)
		return NULL;

	arc4random_buf(buff, len_sp);
	return buff;
}

/**
 * Функция шифрования данных
 * @param open_data 		- данные для шифрования
 * @param len_open_data 	- размер open_data
 * @param key 				- пароль для преобразования в ключ
 * @param len_key 			- размер pass
 * @param len_crypted_data  - размер зашифрованных данных
 * @return 					- зашифрованные данные в формате |синхропосылка (8 байт)|зашифрованные данные|имитозащита (8 байт)|
 */
unsigned char * crypt_data(unsigned char *open_data, int len_open_data, unsigned char *key, int len_key, int *len_crypted_data) {
    unsigned char ctx[kCfb89ContextLen];
    unsigned char imit_ctx[kImit89ContextLen];
	unsigned char * crypted_data = NULL;
	unsigned char * sp = NULL;
    unsigned char * buffer = NULL;
    unsigned char imz[LEN_IMZ_8];
    unsigned int num0 = 0;

    if(open_data == NULL || key == NULL)
        goto error;

	sp = getSP(LEN_SP_8);
	if(sp == NULL)
		return NULL;

	*len_crypted_data = LEN_SP_8 + len_open_data + LEN_IMZ_8;
	crypted_data = (unsigned char *)malloc(*len_crypted_data);
	if(crypted_data == NULL)
		goto error;

    if (len_open_data % 8 != 0) {
        //num0 = ((len_open_data / 8 + 1) * 8) - len_open_data;
        num0 = 8 - (len_open_data & 7);
    }

    if(num0 == 0) {
        buffer = open_data;
    } else {
        buffer = (unsigned char *) malloc(len_open_data + num0);
        memcpy(buffer, open_data, len_open_data);
        memset(buffer + len_open_data, 0, num0);
    }

    if(!cypher_magma_imit_init((unsigned char *)key, LEN_IMZ_8, imit_ctx))
        goto error;
    if(!cypher_imit(imit_ctx, buffer, imz, len_open_data + num0))
        goto error;
    free_imit(imit_ctx);

    if (num0 > 0)
        free(buffer);

	if(!cypher_magma_cfb_init((unsigned char *)key, ctx, kBlockLen89, sp, LEN_SP_8))
		goto error;
	if(!cypher_encr_cfb(ctx, open_data, crypted_data + LEN_SP_8, len_open_data))
		goto error;
	free_cfb(ctx);

	memcpy(crypted_data, sp, LEN_SP_8);
    memcpy(crypted_data + LEN_SP_8 + len_open_data, imz, LEN_IMZ_8);

    free(sp);

	return crypted_data;

error:
	if(crypted_data != NULL)
		free(crypted_data);
	if(sp != NULL)
		free(sp);
    if (num0 > 0)
        free(buffer);
	(*len_crypted_data) = 0;
	return NULL;
}

unsigned char * calculation_hash(unsigned char * data, int len_data) {
	unsigned char * hesh = (unsigned char *)malloc(32);

	HeshStruct HeshData;
	HeshData.Data = data;
	HeshData.DataLen = (unsigned int)len_data;
	HeshData.Hesh = (unsigned char *) hesh;
	HeshData.STATE = 0;
	Hesh341112(HESH_LEN_256, &HeshData);

	return hesh;
}

unsigned char * calculation_hash512(unsigned char * data, int len_data) {
	unsigned char * hesh = (unsigned char *)malloc(64);

	HeshStruct HeshData;
	HeshData.Data = data;
	HeshData.DataLen = (unsigned int)len_data;
	HeshData.Hesh = (unsigned char *) hesh;
	HeshData.STATE = 0;
	Hesh341112(HESH_LEN_512, &HeshData);

	return hesh;
}

unsigned char * hmac512(unsigned char * kbuf, int len_kbuf, unsigned char * tbuf, int len_tbuf) {
	unsigned char * k;
	unsigned char ipad[64];
	unsigned char opad[64];
	unsigned char k_ipad[64];
	unsigned char k_opad[64];
	unsigned char * temp, * hash;

	if (len_kbuf == 0 || len_kbuf > 64 || len_tbuf == 0)
		return NULL;

	k = (unsigned char *) malloc (64);
	memset(k, 0, 64);
	memcpy(k, kbuf, len_kbuf);

	memset(ipad, 0x36, 64);
	memset(opad, 0x5C, 64);

	for (int i = 0; i < 64; i++) {
		k_ipad[i] = k[i] ^ ipad[i];
	}

	for (int i = 0; i < 64; i++) {
		k_opad[i] = k[i] ^ opad[i];
	}

	temp = (unsigned char *) malloc (64 + len_tbuf);
	memcpy(temp, k_ipad, 64);
	memcpy(temp+64, tbuf, len_tbuf);

	hash = calculation_hash512(temp, 64 + len_tbuf);
	free(temp);

	temp = (unsigned char *) malloc (64 + 64);
	memcpy(temp, k_opad, 64);
	memcpy(temp+64, hash, 64);
	free(hash);

	hash = calculation_hash512(temp, 64 + 64);

	free(k);

	return hash;
}

unsigned char init_crypt_pp(unsigned char * key, unsigned char * user_id) {

    if (SecureIdentifyInf_PP != NULL)
        free(SecureIdentifyInf_PP);

    SecureIdentifyInf_PP = (unsigned char *)malloc(264);

    return init_updsch_pp(key, user_id, SecureIdentifyInf_PP);
}

/**
 * Функция шифрования данных
 * @param data		- данные для шифрования
 * @param len_data	- размер данных для шифрования
 * @param key		- ключ шифрования
 * @param len_key	- длина ключа шифрования
 * @param len_crypted_data	- размер зашифрованных данных
 * @return			- зашифрованные данные в формате |62 a7 f3 0c|Синхропосылка 8Б|Имитовставка 4Б|Зашифрованные данные (длина открытых данных 4Б | открытые данные | нули дополняющие до кратности 8)|
 */
unsigned char * crypt(unsigned char * data, unsigned int len_data, unsigned char * key, unsigned int len_key, unsigned int *len_crypted_data) {
	unsigned char * crypted_data = NULL;
	unsigned char imz[LEN_IMZ_4];
	unsigned char sp[LEN_SP_8];
	unsigned char * buffer = NULL;
    unsigned char serial[] = {0x62, 0xA7, 0xF3, 0x0C};
    unsigned int num_of_zero = 0;

#define LEN_OPEN_DATA 4     // Размер поля "Длина открытых данных"

	if (data == NULL || len_data == 0 || key == NULL || len_key != 32)
		return NULL;

    if (len_data <= 4) {
        // Для совместимости работы с СМКИ
        num_of_zero = 16 - (LEN_LEN + len_data);
    } else {
        if ((LEN_LEN + len_data) % 8 != 0)
            num_of_zero = 8 - ((LEN_LEN + len_data) & 7) ;
    }

	*len_crypted_data = sizeof(serial) + sizeof(sp) + sizeof(imz) + LEN_OPEN_DATA + len_data + num_of_zero;
	crypted_data = (unsigned char *)malloc(*len_crypted_data);
	if(crypted_data == NULL)
		goto error;

    if (SecureIdentifyInf_PP == NULL) {
        return NULL;
    }

    memcpy(sp, get_random_pp(SecureIdentifyInf_PP), 8);
    //*(unsigned int *)sp = random(); // Генерация синхропосылки
	//*(unsigned int *)(sp+4) =  *(unsigned int *)sp;

    buffer = (unsigned char *) malloc(LEN_LEN + len_data + num_of_zero);
    memcpy(buffer, (unsigned  char *)&len_data, LEN_LEN);
    memcpy(buffer + LEN_LEN, data, len_data);
    memset(buffer + LEN_LEN + len_data, 0, num_of_zero);

#if defined(CRYPT_GOST28147)
	// Шифрование
	Cript.REGIM	= GAMMIROVANIE_OS_REG;
	Cript.CRYPT	= ENCRYPT;
	Cript.Key	= (unsigned int *) key;
	Cript.Sp	= SP;
	Cript.Din	= data;
	Cript.Dout	= crypted_data;
	Cript.LenBytes = len_data;
	Cript.TR_STATE = TR_NO;
	Cript.Tz		= TABLE;
	Gost28147(&Cript);
#elif defined(CRYPT_MAGMA)
	unsigned char imit_ctx[kImit89ContextLen];
	if(!cypher_magma_imit_init(key, LEN_IMZ_4, imit_ctx))
		goto error;
	if(!cypher_imit(imit_ctx, buffer, imz, LEN_LEN + len_data + num_of_zero))
		goto error;
	free_imit(imit_ctx);

	unsigned char ctx[kCfb89ContextLen];
	if(!cypher_magma_cfb_init(key, ctx, kBlockLen89, sp, LEN_SP_8))
		goto error;

	if(!cypher_encr_cfb(ctx, buffer, crypted_data + LEN_SP_4 + LEN_IMZ_4, LEN_LEN + len_data + num_of_zero))
		goto error;
	free_cfb(ctx);
#endif

	free(buffer);
	memcpy(crypted_data, sp , LEN_SP_4);
	memcpy(crypted_data + LEN_SP_4, imz, LEN_IMZ_4);
	return crypted_data;

error:
	if(crypted_data != NULL) free(crypted_data);
	if(buffer != NULL) free(buffer);

	(*len_crypted_data) = 0;
	return NULL;
}

/**
 * Функция расшифрования данных
 * @param data		- зашифрованные данные в формате |Синхропосылка 4Б|Зашифрованные данные (длина открытых данных 4Б | открытые данные | нули дополняющие до кратности 8)|Имитовставка 4Б|
 * @param len_data	- размер зашифрованных данных
 * @param key		- ключ шифрования
 * @param len_key	- длина ключа шифрования
 * @param len_crypted_data	- размер расшифрованных данных
 * @return			- расшифрованные данные
 */
unsigned char * decrypt(unsigned char * data, unsigned int len_data, unsigned char * key, unsigned int len_key, unsigned int *len_decrypted_data) {
	unsigned char * decrypted_data = NULL;
	unsigned char imz[LEN_IMZ_4];
	unsigned char sp[LEN_SP_8];

	if (data == NULL || len_data < (LEN_IMZ_4 + LEN_SP_4 + 8) || key == NULL || len_key != 32)
		return NULL;

	*len_decrypted_data = len_data - LEN_IMZ_4 - LEN_SP_4;

	if (*len_decrypted_data <= 0)
		return NULL;

	decrypted_data = (unsigned char *) malloc (*len_decrypted_data);
	if(decrypted_data == NULL)
		goto error;

	memcpy(sp, data, LEN_SP_4);
	*(unsigned int *)(sp+4) =  *(unsigned int *)sp;

#if defined(CRYPT_GOST28147)
	// Расшифрование
	Cript.REGIM		= GAMMIROVANIE_OS_REG;
	Cript.CRYPT		= DECRYPT;
	Cript.Key		= (unsigned int *) pass;
	Cript.Sp		= SP;
	Cript.Din		= data;
    Cript.Dout		= decrypted_data;
	Cript.LenBytes 	= len_data;
	Cript.TR_STATE 	= TR_NO;
	Cript.Tz		= TABLE;
	Gost28147(&Cript);
#elif defined(CRYPT_MAGMA)
	unsigned char ctx[kCfb89ContextLen];
	if(!cypher_magma_cfb_init(key, ctx, kBlockLen89, sp, LEN_IMZ_8))
		goto error;

	if(!cypher_decr_cfb(ctx, data + LEN_SP_4 + LEN_IMZ_4, decrypted_data, *len_decrypted_data))
		goto error;
	free_cfb(ctx);
#endif

#if defined(CRYPT_GOST28147)
	GostStruct gostIMZ;
    gostIMZ.REGIM = MAKE_IMZ;
    gostIMZ.Din = buffer;
    gostIMZ.Dout = imz;
    gostIMZ.LenBytes = len_data + num0;
    gostIMZ.TR_STATE = 0;
    gostIMZ.LenIMZ = LEN_IMZ_4;
    gostIMZ.Key = key;
    gostIMZ.Tz = (unsigned char *)TABLE;
    Gost28147(&gostIMZ);
#elif defined(CRYPT_MAGMA)
	unsigned char imit_ctx[kImit89ContextLen];
	if(!cypher_magma_imit_init((unsigned char *)key, LEN_IMZ_4, imit_ctx))
		goto error;
	if(!cypher_imit(imit_ctx, decrypted_data, imz, (*len_decrypted_data)))
		goto error;
	free_imit(imit_ctx);
#endif

	if(*(unsigned int*)(data + LEN_SP_4) != *(unsigned int*)imz) {
		goto error;
	}

	*len_decrypted_data = *(unsigned int*)decrypted_data;

	return decrypted_data;

	error:
	if(decrypted_data != NULL) free(decrypted_data);

	(*len_decrypted_data) = 0;
	return NULL;
}
