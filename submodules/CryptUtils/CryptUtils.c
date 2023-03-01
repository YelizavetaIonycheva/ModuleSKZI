#include <stdlib.h>
#include <string.h>
#include <crc32.h>

#include "CryptUtils.h"

#include "Hesh341112.h"

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

/**
 * Функция расшифрования файлов М и С
 * @param crypted_kompl_keys 		- массив файлов М и С
 * @param len_crypted_kompl_keys 	- размер crypted_kompl_keys
 * @return							- массив расшифрованных файлов М и С
 */
//unsigned char * decrypt_kompl_keys(unsigned char *crypted_kompl_keys, int len_crypted_kompl_keys) {
//    unsigned char imz[4];
//    unsigned char * buffer = NULL;
//	int  sdvig;
//	unsigned short numOfKompl;
//	unsigned char sp[8];
//
//#if defined(CRYPT_GOST28147)
//	unsigned char table[8][16];
//    int index;
//#endif
//
//    if(crypted_kompl_keys == NULL)
//        return NULL;
//
//	// Ключевые файлы были расшифрованы
//    sdvig = 0; // сдвиг на начало очередного файла М
//
//	while(len_crypted_kompl_keys - sdvig > 0) {
//        buffer = crypted_kompl_keys + sdvig;
//        // buffer сылается на контрольную сумму КИ-М
//        //Проверка контрольной суммы КИ-М на поля 2-9
//        if (*(unsigned int *) buffer != KS_MOD32(((unsigned short *) (buffer + 4)), 78, 0, 1)) {
//            return NULL;
//        }
//
//        //Проверка контрольной суммы КИ-C на поля 2-11
//        if (*(unsigned int *) (buffer + 160) !=
//            KS_MOD32(((unsigned short *) (buffer + 164)), 78, 0, 1)) {
//            return NULL;
//        }
//
//        // Снятие маск с полей 9,10 и 11 КИ-С
//        for (int i = 0; i < 32; i++) {
//            *(buffer + 192 + i) = (*(buffer + 192 + i)) ^ (*(buffer + 32 + i));
//            *(buffer + 224 + i) = (*(buffer + 224 + i)) ^ (*(buffer + 64 + i));
//            *(buffer + 256 + i) = (*(buffer + 256 + i)) ^ (*(buffer + 96 + i));
//            *(buffer + 288 + i) = (*(buffer + 288 + i)) ^ (*(buffer + 128 + i));
//        }
//
//        numOfKompl = *(unsigned short *) (buffer + 174);
//
//        //Проверка контрольной суммы КИ-C на поле 12
//        if (*(unsigned int *) (buffer + 176) !=
//            KS_MOD32(((unsigned short *) (buffer + 320)), 24 * numOfKompl, 0, 1)) {
//            return NULL;
//        }
//
//#if defined(CRYPT_GOST28147)
//        // Подготовка таблицы замены
//        // buffer сылается на таблицу замен КИ-С
//        buffer = crypted_kompl_keys + 256 + sdvig;
//        index = 0;
//        for (int j = 0; j < 16; j++) {
//            for (int i = 0; i < 8; i += 2) {
//                table[i][j] = buffer[index] & 0x0F;
//                table[i + 1][j] = (buffer[index] >> 4) & 0x0F;
//                index++;
//            }
//        }
//#endif
//        // buffer сылается на ключевые записи КИ-С
//        buffer = crypted_kompl_keys + 320 + sdvig;
//
//        for (int i = 0; i < numOfKompl; i++) {
//            //Проверка контрольной суммы на поле 2 - 4
//            if (*(unsigned int *) buffer != KS_MOD32(((unsigned short *) (buffer + 4)), 22, 0, 1)) {
//                return NULL;
//            }
//
//            // Расшифрование поля 4
//            *(unsigned int *) sp = *(unsigned int *) (buffer + 8);
//            *(unsigned int *) (sp + 4) = *(unsigned int *) (buffer + 12);
//
//#if defined(CRYPT_GOST28147)
//			GostStruct gostDECR;
//            gostDECR.REGIM  = GAMMIROVANIE_OS_REG;
//            gostDECR.CRYPT  = DECRYPT;
//            gostDECR.Sp     = (unsigned int *)sp;
//            gostDECR.Din    = buffer + 16;
//            gostDECR.Dout   = buffer + 16;
//            gostDECR.LenBytes = 32;
//            gostDECR.TR_STATE = 0;
//            gostDECR.Key    = (unsigned int *)(crypted_kompl_keys + sdvig + 192);
//            gostDECR.Tz     = (unsigned char *)table;
//            Gost28147(&gostDECR);
//
//			GostStruct gostIMZ;
//            gostIMZ.REGIM   = MAKE_IMZ;
//            gostIMZ.Din     = buffer + 16;
//            gostIMZ.Dout    = imz;
//            gostIMZ.LenBytes = 32;
//            gostIMZ.TR_STATE = 0;
//            gostIMZ.LenIMZ  = LEN_IMZ_4;
//            gostIMZ.Key     = (unsigned int *)(crypted_kompl_keys + sdvig + 192);
//            gostIMZ.Tz      = (unsigned char *)table;
//            Gost28147(&gostIMZ);
//#elif defined(CRYPT_MAGMA)
//            unsigned char ctx[kCfb89ContextLen];
//            unsigned char temp_key[32] = {0};
//            if (!cypher_magma_cfb_init(crypted_kompl_keys + sdvig + 192, ctx, kBlockLen89, sp, 8))
//                return NULL;
//            if (!cypher_decr_cfb(ctx, buffer + 16, temp_key, 32))
//                return NULL;
//            free_cfb(ctx);
//            memcpy(buffer + 16, temp_key, 32);
//
//            if (!cypher_magma_imit_init(crypted_kompl_keys + sdvig  + 192, LEN_IMZ_4, ctx))
//                return NULL;
//            if (!cypher_imit(ctx, buffer + 16, imz, 32))
//                return NULL;
//            free_imit(ctx);
//#endif
//
//            if (*(unsigned int *) (buffer + 4) != *(unsigned int *) (imz)) {
//                return NULL;
//            }
//
//            buffer += 48;
//        }
//
//        sdvig += 326 + numOfKompl*48;
//    }
//
//    return crypted_kompl_keys;
//}

/**
 * Функций поиска и удаление найденного ключа
 * @param key_delete        - описатель удаляемого ключа
 * @param len_key_delete    - размер описателя key_delete
 * @param key_data          - массив ключей
 * @param len_key_data      - размер key_data
 * @param len_new_keys      - размер обновленное массива ключей
 * @return                  - обновленный массив ключей
 */
//unsigned char * search_and_delete_key(unsigned char * key_delete, int len_key_delete, unsigned char * key_data, int len_key_data, int * len_new_keys) {
//	KEY_portal * key_for_deleting;
//	BLOCKNOTE * blocknote;
//	unsigned char * new_keys = NULL;
//	int size_new_keys = 0;
//	int sdvig, sdvig_new_keys, size_copy;
//	unsigned int crc;
//
//	if(key_delete == NULL || len_key_delete != sizeof(KEY_portal) || key_data == NULL || len_key_data == 0)
//		return NULL;
//
//	key_for_deleting = (KEY_portal*)key_delete;
//	sdvig = 0;
//
//	while((len_key_data - sdvig) > 0) {
//		blocknote = (BLOCKNOTE *)(key_data + sdvig);
//
//		if(!(key_for_deleting->name[0] == blocknote->name[0] &&
//			 key_for_deleting->name[1] == blocknote->name[1] &&
//			 key_for_deleting->name[2] == blocknote->name[3] &&
//		   	 key_for_deleting->serial[4] == blocknote->serial[0] &&
//		     key_for_deleting->serial[5] == blocknote->serial[1] &&
//		     key_for_deleting->serial[6] == blocknote->serial[2] &&
//		     key_for_deleting->serial[7] == blocknote->serial[3] &&
//		     key_for_deleting->kompl == blocknote->kompl)) {
//				size_new_keys += 326 + blocknote->kol * 48;
//				sdvig += 326 + blocknote->kol * 48;
//				continue;
//		}
//
//		// Ключ найден, пометим его стиранием crc
//		memset(blocknote->crc, 0, 4);
//		sdvig += 326 + blocknote->kol * 48;
//	}
//
//	if(size_new_keys == len_key_data)
//		return NULL;  //Ключ для удаления не найден
//
//	new_keys = (unsigned char *)malloc(size_new_keys);
//	sdvig = 0;
//	sdvig_new_keys = 0;
//
//	while((len_key_data - sdvig) > 0) {
//		blocknote = (BLOCKNOTE *)(key_data + sdvig);
//		crc = *(unsigned int *)(blocknote->crc);
//		if(crc != 0) {
//			size_copy = 326 + blocknote->kol * 48;
//			memcpy(new_keys + sdvig_new_keys, key_data + sdvig, size_copy);
//			sdvig_new_keys += size_copy;
//		}
//
//		sdvig += 326 + blocknote->kol * 48;
//	}
//
//	*len_new_keys = size_new_keys;
//	return new_keys;
//}

/**
 * Функция изменения срока работы ключа
 * @param key_edit 		- описатель ключа, в котором необходимо поменять срок работы
 * @param len_key_edit 	- размер key_edit
 * @param key_data 		- массив сохраненных ключей
 * @param len_key_data  - размер key_data
 * @param len_new_keys  - размер обновленного массива ключей
 * @return 				- обновленный массив ключей
 */
//unsigned char * search_and_edit_key(unsigned char * key_edit, int len_key_edit, unsigned char * key_data, int len_key_data) {
//	KEY_portal * key_for_edit;
//	BLOCKNOTE * blocknote;
//	unsigned char * new_keys = NULL;
//	int sdvig=0;
//
//	if(key_edit == NULL || len_key_edit != sizeof(KEY_portal) || key_data == NULL || len_key_data == 0)
//		return NULL;
//
//	key_for_edit = (KEY_portal*)key_edit;
//
//	while((len_key_data - sdvig) > 0) {
//		blocknote = (BLOCKNOTE *)(key_data + sdvig);
//
//		sdvig = sdvig + 320 + blocknote->kol * 48 + 6;
//		if((len_key_data - sdvig) < 0)
//			return NULL;
//
//		if(!(key_for_edit->name[0] == blocknote->name[0] &&
//			 key_for_edit->name[1] == blocknote->name[1] &&
//			 key_for_edit->name[2] == blocknote->name[3] &&
//			 key_for_edit->serial[4] == blocknote->serial[0] &&
//			 key_for_edit->serial[5] == blocknote->serial[1] &&
//			 key_for_edit->serial[6] == blocknote->serial[2] &&
//			 key_for_edit->serial[7] == blocknote->serial[3] &&
//			 key_for_edit->kompl == blocknote->kompl)) {
//			continue;
//		}
//
//		// Ключ найден, меняем даты
//		//memcpy(key_data + sdvig - 6, key_edit + 20, 6);
//		memcpy(key_data + sdvig - 6, key_edit + 20, 3);
//		memcpy(key_data + sdvig - 3, key_edit + 23, 3);
//
//		new_keys = key_data;
//		/*new_keys = (unsigned char *)malloc(len_key_data);
//		memcpy(new_keys, key_data, len_key_data);
//		*len_new_keys = len_key_data;*/
//		break;
//	}
//
//	return new_keys;
//}

/**
 *
 * @param key_edit 			- описатель ключа, которого необходимо добавить
 * @param len_key_edit 		- размер key_edit
 * @param add_key_data 		- ключевые данные, которые будут добавлены
 * @param len_add_key_data 	- размер add_key_data
 * @param old_key_data 		- старые ключевые данные
 * @param len_old_key_data 	- размер old_key_data
 * @param len_new_keys 		- размер новых ключевых данных
 * @return 					- новые ключевые данные
 */
//unsigned char * add_key(unsigned char * key_edit, int len_key_edit, unsigned char * add_key_data, int len_add_key_data, unsigned char * old_key_data, int len_old_key_data, int * len_new_keys) {
//    unsigned char * new_keys = NULL;
//
//    if(key_edit == NULL || len_key_edit != sizeof(KEY_portal) || add_key_data == NULL || len_add_key_data == 0 || old_key_data == NULL || len_old_key_data == 0)
//        return NULL;
//	*len_new_keys = len_old_key_data + len_add_key_data + 6;
//    new_keys = (unsigned char *)malloc(*len_new_keys);
//    memcpy(new_keys, old_key_data, len_old_key_data);
//    memcpy(new_keys+len_old_key_data, add_key_data, len_add_key_data);
//    memcpy(new_keys+len_old_key_data+len_add_key_data, key_edit+20, 6);
//
//    return new_keys;
//}

/**
 * Функция проверки даты окончания срока работы ключа
 * @param now_date 		- текущая дата now_date[0] - год, now_date[1] - месяц, now_date[2] - день
 * @param key_date_end
 * @return
 */
//static unsigned char key_is_working(unsigned char * now_date, unsigned char * key_date_end) {
//	int _now_date, _key_date_end;
//	_now_date 		= (now_date[0] << 16) | (now_date[1] << 8) | (now_date[2]);
//	_key_date_end 	= (key_date_end[0] << 16) | (key_date_end[1] << 8) | (key_date_end[2]);
//
//	if(_key_date_end == 0)
//		return 1;
//	if(_now_date < _key_date_end)
//		return 1;
//	return 0;
//}

/**
 * Функция проверки срока работы текущего ключевого блокнота, если его срок работы вышел, замена на очередной
 * @param key_data          - массив ключей (первый ключ - текущий)
 * @param len_key_data      - размер key_data
 * @param now_date          - текущая дата
 * @param len_now_date      - размер now_date
 * @param len_new_key_data  - размер обновленного массива ключей
 * @return                  - обновленный массив ключей
 */
//unsigned char * check_key_date(unsigned char * key_data, int len_key_data, unsigned char * now_date, int len_now_date, int * len_new_key_data) {
//	BLOCKNOTE * blocknote;
//	unsigned char * date;
//	unsigned char * new_key_data = NULL;
//	int sdvig, index, len_blocknote;
//
//	if(key_data == NULL || len_key_data == 0 || now_date == NULL || len_now_date != 3)
//		return NULL;
//
//	blocknote = (BLOCKNOTE *)key_data;
//	date = (key_data + 320 + 3 + blocknote->kol * 48);
//	//date = (key_data + 320 + blocknote->kol * 48); // Для теста
//
//	// Проверка текущего блокнота
//	if(key_is_working(now_date, date))
//		return NULL;
//	// Срок работы текущего ключа завершен
//
//	// Поиск первого рабочего ключа
//	sdvig = 326 + blocknote->kol * 48; // Пропуск нерабочего ключа
//
//	while((len_key_data - sdvig) > 0) {
//		blocknote = (BLOCKNOTE *)(key_data + sdvig);
//		sdvig = sdvig + 320 + blocknote->kol * 48 + 6;
//
//		date = (key_data + sdvig - 6); // Дата начала работы
//
//		if(!key_is_working(now_date, date)) {
//			*len_new_key_data = len_key_data - 320 - 6 - blocknote->kol * 48;
//			new_key_data = (unsigned char *)malloc(*len_new_key_data);
//
//			index = 320 + blocknote->kol * 48 + 6;
//			memcpy(new_key_data, (unsigned char *)blocknote, index); // Запись найденного блокнота в раздел текущего рабочего блокнота
//			memset((unsigned char *)blocknote, 0, 4);  // Пометка, что данный блокнот используется в качестве текущего и его не нужно копировать
//
//			// Копирование оставшихся очередных блокнотов в раздел очередных блокнотов
//			sdvig = 326 + blocknote->kol * 48; // Пропуск текущего нерабочего ключа
//
//			while((len_key_data - sdvig) > 0) {
//				blocknote = (BLOCKNOTE *)(key_data + sdvig);
//				len_blocknote = 320 + blocknote->kol * 48 + 6;
//
//				if((*(unsigned int *)blocknote->crc) != 0) {
//					memcpy(new_key_data+index, (unsigned char *)blocknote, len_blocknote); // Запись блокнота в раздел рабочих блокнотов
//					index += len_blocknote;
//				}
//
//				sdvig = sdvig + len_blocknote;
//			}
//
//			break;
//		}
//	}
//
//	return new_key_data;
//}

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

//unsigned char * set_next_key_as_work(unsigned char * key_data, int len_key_data, unsigned char * next_key, int len_next_key, int * len_new_keys) {
//	BLOCKNOTE * blocknote;
//	KEY_portal * next_key_blocknote;
//	unsigned char * new_key_data = NULL;
//	int sdvig, count;
//
//	next_key_blocknote = (KEY_portal *)next_key;
//	// Поиск очередного ключа с которым будет меняться действующий
//	blocknote = (BLOCKNOTE *)key_data;
//	sdvig = 326 + blocknote->kol * 48; // Пропуск действующего ключа
//
//	while((len_key_data - sdvig) > 0) {
//		blocknote = (BLOCKNOTE *)(key_data + sdvig);
//
//		if(next_key_blocknote->name[0] == blocknote->name[0] &&
//		   next_key_blocknote->name[1] == blocknote->name[1] &&
//		   next_key_blocknote->name[2] == blocknote->name[3] &&
//		   next_key_blocknote->serial[4] == blocknote->serial[0] &&
//		   next_key_blocknote->serial[5] == blocknote->serial[1] &&
//		   next_key_blocknote->serial[6] == blocknote->serial[2] &&
//		   next_key_blocknote->serial[7] == blocknote->serial[3] &&
//		   next_key_blocknote->kompl == blocknote->kompl) {
//
//			new_key_data = (unsigned char *)malloc(len_key_data);
//			*len_new_keys = len_key_data;
//			count = 0;
//			memcpy(new_key_data, key_data + sdvig, 326 + blocknote->kol * 48); // Копирование очередного блокнота на место действующего
//			count += 326 + blocknote->kol * 48;
//			// Ключ найден, пометим его стиранием crc
//			memset(blocknote->crc, 0, 4);
//			break;
//		}
//		sdvig = sdvig + 326 + blocknote->kol * 48;
//	}
//
//	if(new_key_data == NULL)
//		return NULL;
//
//	blocknote = (BLOCKNOTE *)key_data;
//	memcpy(new_key_data+count, key_data, 326 + blocknote->kol * 48); // Копирование действующего блокнота сразу после найденного очередного
//	count += 326 + blocknote->kol * 48;
//	sdvig = 326 + blocknote->kol * 48; // Пропуск действующего ключа
//
//	while((len_key_data - sdvig) > 0) {
//		blocknote = (BLOCKNOTE *)(key_data + sdvig);
//		if(*(unsigned int *)(blocknote->crc) != 0) {
//			memcpy(new_key_data+count, key_data + sdvig, 326 + blocknote->kol * 48);
//			count += 326 + blocknote->kol * 48;
//			break;
//		}
//		sdvig = sdvig + 326 + blocknote->kol * 48;
//	}
//
//	return new_key_data;
//}

/**
 * Функция шифрования данных
 * @param data		- данные для шифрования
 * @param len_data	- размер данных для шифрования
 * @param key		- ключ шифрования
 * @param len_key	- длина ключа шифрования
 * @param len_crypted_data	- размер зашифрованных данных
 * @return			- зашифрованные данные в формате |Синхропосылка 4Б|Зашифрованные данные (длина открытых данных 4Б | открытые данные | нули дополняющие до кратности 8)|Имитовставка 4Б|
 */
unsigned char * crypt(unsigned char * data, unsigned int len_data, unsigned char * key, unsigned int len_key, unsigned int *len_crypted_data) {
	unsigned char * crypted_data = NULL;
	unsigned char imz[LEN_IMZ_4];
	unsigned char sp[LEN_SP_8];
	unsigned char * buffer = NULL;

	if (data == NULL || len_data == 0 || key == NULL || len_key != 32)
		return NULL;

    unsigned int num_of_zero = 0;

    if (len_data <= 4) {
        // Для совместимости работы с СМКИ
        num_of_zero = 16 - (LEN_LEN + len_data);
    } else {
        if ((LEN_LEN + len_data) % 8 != 0)
            num_of_zero = 8 - ((LEN_LEN + len_data) & 7) ;
    }

	*len_crypted_data = LEN_SP_4 + LEN_LEN + len_data + num_of_zero + LEN_IMZ_4;
	crypted_data = (unsigned char *)malloc(*len_crypted_data);
	if(crypted_data == NULL)
		goto error;

    *(unsigned int *)sp = random(); // Генерация синхропосылки
	*(unsigned int *)(sp+4) =  *(unsigned int *)sp;

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
