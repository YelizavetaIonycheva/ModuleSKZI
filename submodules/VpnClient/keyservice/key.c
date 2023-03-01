#include <stdlib.h>
#include <string.h>
#include <crc32.h>

#include "IKEv2_Def.h"
#include "key.h"

#include "Hesh341112.h"

#if defined(CRYPT_GOST28147)
#include "Gost28147.h"
#elif defined(CRYPT_MAGMA)
#include "cypher.h"
#include "cypher_magma.h"
#endif

/**
 * Функция расшифрования данных
 * @param crypted_data  		- данные для расшифрования
 * @param len_crypted_data 		- размер зашифрованных данных
 * @param key 					- ключ
 * @param len_key 				- размер key
 * @param len_open_data 		- размер расшифрованных данных
 * @return 						- расшифрованные данные
 */
unsigned char * decrypt_data(unsigned char * crypted_data, int len_crypted_data, unsigned char * key, int len_key, int * len_open_data) {
    unsigned char * open_data = NULL;

	if(crypted_data == NULL || key == NULL)
		goto error;

    *len_open_data = len_crypted_data - 8;

    open_data = (unsigned char *)malloc(*len_open_data);
    if(open_data == NULL)
        goto error;

#if defined(CRYPT_GOST28147)
    GostStruct gostDECR;
    gostDECR.REGIM = GAMMIROVANIE_OS_REG;
    gostDECR.CRYPT = DECRYPT;
    gostDECR.Sp = (unsigned int*)crypted_data;
    gostDECR.Din = crypted_data+8;
    gostDECR.Dout = open_data;
    gostDECR.LenBytes = *len_open_data;
    gostDECR.TR_STATE = 0;
    gostDECR.Key = (unsigned int *)key;
    gostDECR.Tz = (unsigned char *)TABLE;
    Gost28147(&gostDECR);
#elif defined(CRYPT_MAGMA)
    unsigned char ctx[kCfb89ContextLen];
    if(!cypher_magma_cfb_init(key, ctx, kBlockLen89, crypted_data, 8))
        goto error;
    if(!cypher_decr_cfb(ctx, crypted_data+8, open_data, *len_open_data))
        goto error;
    free_cfb(ctx);
#endif

    return open_data;

error:
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
 * @return 					- зашифрованные данные
 */
unsigned char * crypt_data(unsigned char *open_data, int len_open_data,
						   unsigned char *key, int len_key, int *len_crypted_data) {
	unsigned char * crypted_data = NULL;
	unsigned char * sp = NULL;



	sp = getSP(8);
	if(sp == NULL)
		return NULL;

	*len_crypted_data = len_open_data + 8;
	crypted_data = (unsigned char *)malloc(*len_crypted_data);
	if(crypted_data == NULL)
		goto error;

#if defined(CRYPT_GOST28147)
	// Шифрование
    GostStruct Cript;
	Cript.REGIM	= GAMMIROVANIE_OS_REG;
	Cript.CRYPT	= ENCRYPT;
	Cript.Key	= key;
	Cript.Sp	= (unsigned int *)sp;
	Cript.Din	= open_data;
	Cript.Dout	= crypted_data+8;
	Cript.LenBytes = len_open_data;
	Cript.TR_STATE = TR_NO;
	Cript.Tz	= (unsigned char *)TABLE;
	Gost28147(&Cript);
#elif defined(CRYPT_MAGMA)
	unsigned char ctx[kCfb89ContextLen];
	if(!cypher_magma_cfb_init((unsigned char *)key, ctx, kBlockLen89, sp, 8))
		goto error;
	if(!cypher_encr_cfb(ctx, open_data, crypted_data+8, len_open_data))
		goto error;
	free_cfb(ctx);
#endif

	memcpy(crypted_data, sp, 8);

	return crypted_data;

error:
	if(crypted_data != NULL) {
		free(crypted_data);
	}

	if(sp != NULL) {
		free(sp);
	}

	(*len_crypted_data) = 0;
	return NULL;
}

/**
 * Функция расшифрования файлов М и С
 * @param crypted_kompl_keys 		- массив файлов М и С
 * @param len_crypted_kompl_keys 	- размер crypted_kompl_keys
 * @return							- массив расшифрованных файлов М и С
 */
unsigned char * decrypt_kompl_keys(unsigned char *crypted_kompl_keys, int len_crypted_kompl_keys) {
    unsigned char imz[4];
    unsigned char * buffer = NULL;
	int  sdvig;
	unsigned short numOfKompl;
	unsigned char sp[8];

#if defined(CRYPT_GOST28147)
	unsigned char table[8][16];
    int index;
#endif

    if(crypted_kompl_keys == NULL)
        return NULL;

	// Ключевые файлы были расшифрованы
    sdvig = 0; // сдвиг на начало очередного файла М

	while(len_crypted_kompl_keys - sdvig > 0) {
        buffer = crypted_kompl_keys + sdvig;
        // buffer сылается на контрольную сумму КИ-М
        //Проверка контрольной суммы КИ-М на поля 2-9
        if (*(unsigned int *) buffer != KS_MOD32(((unsigned short *) (buffer + 4)), 78, 0, 1)) {
            return NULL;
        }

        //Проверка контрольной суммы КИ-C на поля 2-11
        if (*(unsigned int *) (buffer + 160) !=
            KS_MOD32(((unsigned short *) (buffer + 164)), 78, 0, 1)) {
            return NULL;
        }

        // Снятие маск с полей 9,10 и 11 КИ-С
        for (int i = 0; i < 32; i++) {
            *(buffer + 192 + i) = (*(buffer + 192 + i)) ^ (*(buffer + 32 + i));
            *(buffer + 224 + i) = (*(buffer + 224 + i)) ^ (*(buffer + 64 + i));
            *(buffer + 256 + i) = (*(buffer + 256 + i)) ^ (*(buffer + 96 + i));
            *(buffer + 288 + i) = (*(buffer + 288 + i)) ^ (*(buffer + 128 + i));
        }

        numOfKompl = *(unsigned short *) (buffer + 174);

        //Проверка контрольной суммы КИ-C на поле 12
        if (*(unsigned int *) (buffer + 176) !=
            KS_MOD32(((unsigned short *) (buffer + 320)), 24 * numOfKompl, 0, 1)) {
            return NULL;
        }

#if defined(CRYPT_GOST28147)
        // Подготовка таблицы замены
        // buffer сылается на таблицу замен КИ-С
        buffer = crypted_kompl_keys + 256 + sdvig;
        index = 0;
        for (int j = 0; j < 16; j++) {
            for (int i = 0; i < 8; i += 2) {
                table[i][j] = buffer[index] & 0x0F;
                table[i + 1][j] = (buffer[index] >> 4) & 0x0F;
                index++;
            }
        }
#endif
        // buffer сылается на ключевые записи КИ-С
        buffer = crypted_kompl_keys + 320 + sdvig;

        for (int i = 0; i < numOfKompl; i++) {
            //Проверка контрольной суммы на поле 2 - 4
            if (*(unsigned int *) buffer != KS_MOD32(((unsigned short *) (buffer + 4)), 22, 0, 1)) {
                return NULL;
            }

            // Расшифрование поля 4
            *(unsigned int *) sp = *(unsigned int *) (buffer + 8);
            *(unsigned int *) (sp + 4) = *(unsigned int *) (buffer + 12);

#if defined(CRYPT_GOST28147)
			GostStruct gostDECR;
            gostDECR.REGIM  = GAMMIROVANIE_OS_REG;
            gostDECR.CRYPT  = DECRYPT;
            gostDECR.Sp     = (unsigned int *)sp;
            gostDECR.Din    = buffer + 16;
            gostDECR.Dout   = buffer + 16;
            gostDECR.LenBytes = 32;
            gostDECR.TR_STATE = 0;
            gostDECR.Key    = (unsigned int *)(crypted_kompl_keys + sdvig + 192);
            gostDECR.Tz     = (unsigned char *)table;
            Gost28147(&gostDECR);

			GostStruct gostIMZ;
            gostIMZ.REGIM   = MAKE_IMZ;
            gostIMZ.Din     = buffer + 16;
            gostIMZ.Dout    = imz;
            gostIMZ.LenBytes = 32;
            gostIMZ.TR_STATE = 0;
            gostIMZ.LenIMZ  = LEN_IMZ_4;
            gostIMZ.Key     = (unsigned int *)(crypted_kompl_keys + sdvig + 192);
            gostIMZ.Tz      = (unsigned char *)table;
            Gost28147(&gostIMZ);
#elif defined(CRYPT_MAGMA)
            unsigned char ctx[kCfb89ContextLen];
            unsigned char temp_key[32] = {0};
            if (!cypher_magma_cfb_init(crypted_kompl_keys + sdvig + 192, ctx, kBlockLen89, sp, 8))
                return NULL;
            if (!cypher_decr_cfb(ctx, buffer + 16, temp_key, 32))
                return NULL;
            free_cfb(ctx);
            memcpy(buffer + 16, temp_key, 32);

            if (!cypher_magma_imit_init(crypted_kompl_keys + sdvig  + 192, LEN_IMZ_4, ctx))
                return NULL;
            if (!cypher_imit(ctx, buffer + 16, imz, 32))
                return NULL;
            free_imit(ctx);
#endif

            if (*(unsigned int *) (buffer + 4) != *(unsigned int *) (imz)) {
                return NULL;
            }

            buffer += 48;
        }

        sdvig += 326 + numOfKompl*48;
    }

    return crypted_kompl_keys;
}



/**
 * Функций поиска и удаление найденного ключа
 * @param key_delete        - описатель удаляемого ключа
 * @param len_key_delete    - размер описателя key_delete
 * @param key_data          - массив ключей
 * @param len_key_data      - размер key_data
 * @param len_new_keys      - размер обновленное массива ключей
 * @return                  - обновленный массив ключей
 */
unsigned char * search_and_delete_key(unsigned char * key_delete, int len_key_delete, unsigned char * key_data, int len_key_data, int * len_new_keys) {
	KEY_portal * key_for_deleting;
	BLOCKNOTE * blocknote;
	unsigned char * new_keys = NULL;
	int size_new_keys = 0; 
	int sdvig, sdvig_new_keys, size_copy;
	unsigned int crc;
	
	if(key_delete == NULL || len_key_delete != sizeof(KEY_portal) || key_data == NULL || len_key_data == 0)
		return NULL;
	
	key_for_deleting = (KEY_portal*)key_delete;
	sdvig = 0;
	
	while((len_key_data - sdvig) > 0) {
		blocknote = (BLOCKNOTE *)(key_data + sdvig);
		
		if(!(key_for_deleting->name[0] == blocknote->name[0] &&
			 key_for_deleting->name[1] == blocknote->name[1] &&
			 key_for_deleting->name[2] == blocknote->name[3] &&
		   	 key_for_deleting->serial[4] == blocknote->serial[0] &&
		     key_for_deleting->serial[5] == blocknote->serial[1] &&
		     key_for_deleting->serial[6] == blocknote->serial[2] &&
		     key_for_deleting->serial[7] == blocknote->serial[3] &&
		     key_for_deleting->kompl == blocknote->kompl)) {
				size_new_keys += 326 + blocknote->kol * 48;
				sdvig += 326 + blocknote->kol * 48;
				continue;
		}
		
		// Ключ найден, пометим его стиранием crc
		memset(blocknote->crc, 0, 4);
		sdvig += 326 + blocknote->kol * 48;
	}
	
	if(size_new_keys == len_key_data)
		return NULL;  //Ключ для удаления не найден

	new_keys = (unsigned char *)malloc(size_new_keys);
	sdvig = 0;
	sdvig_new_keys = 0;

	while((len_key_data - sdvig) > 0) {
		blocknote = (BLOCKNOTE *)(key_data + sdvig);
		crc = *(unsigned int *)(blocknote->crc);
		if(crc != 0) {
			size_copy = 326 + blocknote->kol * 48;
			memcpy(new_keys + sdvig_new_keys, key_data + sdvig, size_copy);
			sdvig_new_keys += size_copy;
		}
		
		sdvig += 326 + blocknote->kol * 48;
	}
	
	*len_new_keys = size_new_keys;
	return new_keys;
}

/**
 * Функция удаления ключей, находящихся в списке СКН
 * @param key_data      - массив сохраненных ключей
 * @param len_keys      - размер key_data
 * @param len_new_keys  - размер обновленного массива ключей
 * @return              - обновленный массив ключей
 */
unsigned char * check_key_for_skn(unsigned char * key_data, int len_keys, int * len_new_keys) {
	unsigned char * new_keys = NULL, * temp_key_data;
	int  i, len_temp_key_data;

	*len_new_keys = 0;
	len_temp_key_data = len_keys;
	temp_key_data = key_data;

	if(compr_keylist.numEntries != 0) {
		for(i = 0; i < compr_keylist.numEntries; i++) {
			temp_key_data = search_and_delete_key((unsigned char *)&compr_keylist.keyEntry[i], sizeof(keylist_entry_t), temp_key_data, len_temp_key_data, &len_temp_key_data);

			if(temp_key_data != NULL) {
				if(new_keys != NULL) {
					free(new_keys);
					new_keys = NULL;
				}
				new_keys = temp_key_data;
				*len_new_keys = len_temp_key_data;
			}
		}
	}

	return new_keys;
}

/**
 * Функция изменения срока работы ключа
 * @param key_edit 		- описатель ключа, в котором необходимо поменять срок работы
 * @param len_key_edit 	- размер key_edit
 * @param key_data 		- массив сохраненных ключей
 * @param len_key_data  - размер key_data
 * @param len_new_keys  - размер обновленного массива ключей
 * @return 				- обновленный массив ключей
 */
unsigned char * search_and_edit_key(unsigned char * key_edit, int len_key_edit, unsigned char * key_data, int len_key_data) {
	KEY_portal * key_for_edit;
	BLOCKNOTE * blocknote;
	unsigned char * new_keys = NULL;
	int sdvig=0;

	if(key_edit == NULL || len_key_edit != sizeof(KEY_portal) || key_data == NULL || len_key_data == 0)
		return NULL;

	key_for_edit = (KEY_portal*)key_edit;

	while((len_key_data - sdvig) > 0) {
		blocknote = (BLOCKNOTE *)(key_data + sdvig);

		sdvig = sdvig + 320 + blocknote->kol * 48 + 6;
		if((len_key_data - sdvig) < 0)
			return NULL;

		if(!(key_for_edit->name[0] == blocknote->name[0] &&
			 key_for_edit->name[1] == blocknote->name[1] &&
			 key_for_edit->name[2] == blocknote->name[3] &&
			 key_for_edit->serial[4] == blocknote->serial[0] &&
			 key_for_edit->serial[5] == blocknote->serial[1] &&
			 key_for_edit->serial[6] == blocknote->serial[2] &&
			 key_for_edit->serial[7] == blocknote->serial[3] &&
			 key_for_edit->kompl == blocknote->kompl)) {
			continue;
		}

		// Ключ найден, меняем даты
		//memcpy(key_data + sdvig - 6, key_edit + 20, 6);
		memcpy(key_data + sdvig - 6, key_edit + 20, 3);
		memcpy(key_data + sdvig - 3, key_edit + 23, 3);

		new_keys = key_data;
		/*new_keys = (unsigned char *)malloc(len_key_data);
		memcpy(new_keys, key_data, len_key_data);
		*len_new_keys = len_key_data;*/
		break;
	}

	return new_keys;
}

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
unsigned char * add_key(unsigned char * key_edit, int len_key_edit, unsigned char * add_key_data, int len_add_key_data, unsigned char * old_key_data, int len_old_key_data, int * len_new_keys) {
    unsigned char * new_keys = NULL;

    if(key_edit == NULL || len_key_edit != sizeof(KEY_portal) || add_key_data == NULL || len_add_key_data == 0 || old_key_data == NULL || len_old_key_data == 0)
        return NULL;
	*len_new_keys = len_old_key_data + len_add_key_data + 6;
    new_keys = (unsigned char *)malloc(*len_new_keys);
    memcpy(new_keys, old_key_data, len_old_key_data);
    memcpy(new_keys+len_old_key_data, add_key_data, len_add_key_data);
    memcpy(new_keys+len_old_key_data+len_add_key_data, key_edit+20, 6);

    return new_keys;
}

/**
 * Функция проверки даты окончания срока работы ключа
 * @param now_date 		- текущая дата now_date[0] - год, now_date[1] - месяц, now_date[2] - день
 * @param key_date_end
 * @return
 */
static unsigned char key_is_working(unsigned char * now_date, unsigned char * key_date_end) {
	int _now_date, _key_date_end;
	_now_date 		= (now_date[0] << 16) | (now_date[1] << 8) | (now_date[2]);
	_key_date_end 	= (key_date_end[0] << 16) | (key_date_end[1] << 8) | (key_date_end[2]);

	if(_key_date_end == 0)
		return 1;
	if(_now_date < _key_date_end)
		return 1;
	return 0;
}

/**
 * Функция проверки срока работы текущего ключевого блокнота, если его срок работы вышел, замена на очередной
 * @param key_data          - массив ключей (первый ключ - текущий)
 * @param len_key_data      - размер key_data
 * @param now_date          - текущая дата
 * @param len_now_date      - размер now_date
 * @param len_new_key_data  - размер обновленного массива ключей
 * @return                  - обновленный массив ключей
 */
unsigned char * check_key_date(unsigned char * key_data, int len_key_data, unsigned char * now_date, int len_now_date, int * len_new_key_data) {
	BLOCKNOTE * blocknote;
	unsigned char * date;
	unsigned char * new_key_data = NULL;
	int sdvig, index, len_blocknote;

	if(key_data == NULL || len_key_data == 0 || now_date == NULL || len_now_date != 3)
		return NULL;

	blocknote = (BLOCKNOTE *)key_data;
	date = (key_data + 320 + 3 + blocknote->kol * 48);
	//date = (key_data + 320 + blocknote->kol * 48); // Для теста

	// Проверка текущего блокнота
	if(key_is_working(now_date, date))
		return NULL;
	// Срок работы текущего ключа завершен

	// Поиск первого рабочего ключа
	sdvig = 326 + blocknote->kol * 48; // Пропуск нерабочего ключа

	while((len_key_data - sdvig) > 0) {
		blocknote = (BLOCKNOTE *)(key_data + sdvig);
		sdvig = sdvig + 320 + blocknote->kol * 48 + 6;

		date = (key_data + sdvig - 6); // Дата начала работы

		if(!key_is_working(now_date, date)) {
			*len_new_key_data = len_key_data - 320 - 6 - blocknote->kol * 48;
			new_key_data = (unsigned char *)malloc(*len_new_key_data);

			index = 320 + blocknote->kol * 48 + 6;
			memcpy(new_key_data, (unsigned char *)blocknote, index); // Запись найденного блокнота в раздел текущего рабочего блокнота
			memset((unsigned char *)blocknote, 0, 4);  // Пометка, что данный блокнот используется в качестве текущего и его не нужно копировать

			// Копирование оставшихся очередных блокнотов в раздел очередных блокнотов
			sdvig = 326 + blocknote->kol * 48; // Пропуск текущего нерабочего ключа

			while((len_key_data - sdvig) > 0) {
				blocknote = (BLOCKNOTE *)(key_data + sdvig);
				len_blocknote = 320 + blocknote->kol * 48 + 6;

				if((*(unsigned int *)blocknote->crc) != 0) {
					memcpy(new_key_data+index, (unsigned char *)blocknote, len_blocknote); // Запись блокнота в раздел рабочих блокнотов
					index += len_blocknote;
				}

				sdvig = sdvig + len_blocknote;
			}

			break;
		}
	}

	return new_key_data;
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


unsigned char * set_next_key_as_work(unsigned char * key_data, int len_key_data, unsigned char * next_key, int len_next_key, int * len_new_keys) {
	BLOCKNOTE * blocknote;
	KEY_portal * next_key_blocknote;
	unsigned char * new_key_data = NULL;
	int sdvig, count;

	next_key_blocknote = (KEY_portal *)next_key;
	// Поиск очередного ключа с которым будет меняться действующий
	blocknote = (BLOCKNOTE *)key_data;
	sdvig = 326 + blocknote->kol * 48; // Пропуск действующего ключа

	while((len_key_data - sdvig) > 0) {
		blocknote = (BLOCKNOTE *)(key_data + sdvig);

		if(next_key_blocknote->name[0] == blocknote->name[0] &&
		   next_key_blocknote->name[1] == blocknote->name[1] &&
		   next_key_blocknote->name[2] == blocknote->name[3] &&
		   next_key_blocknote->serial[4] == blocknote->serial[0] &&
		   next_key_blocknote->serial[5] == blocknote->serial[1] &&
		   next_key_blocknote->serial[6] == blocknote->serial[2] &&
		   next_key_blocknote->serial[7] == blocknote->serial[3] &&
		   next_key_blocknote->kompl == blocknote->kompl) {

			new_key_data = (unsigned char *)malloc(len_key_data);
			*len_new_keys = len_key_data;
			count = 0;
			memcpy(new_key_data, key_data + sdvig, 326 + blocknote->kol * 48); // Копирование очередного блокнота на место действующего
			count += 326 + blocknote->kol * 48;
			// Ключ найден, пометим его стиранием crc
			memset(blocknote->crc, 0, 4);
			break;
		}
		sdvig = sdvig + 326 + blocknote->kol * 48;
	}

	if(new_key_data == NULL)
		return NULL;

	blocknote = (BLOCKNOTE *)key_data;
	memcpy(new_key_data+count, key_data, 326 + blocknote->kol * 48); // Копирование действующего блокнота сразу после найденного очередного
	count += 326 + blocknote->kol * 48;
	sdvig = 326 + blocknote->kol * 48; // Пропуск действующего ключа

	while((len_key_data - sdvig) > 0) {
		blocknote = (BLOCKNOTE *)(key_data + sdvig);
		if(*(unsigned int *)(blocknote->crc) != 0) {
			memcpy(new_key_data+count, key_data + sdvig, 326 + blocknote->kol * 48);
			count += 326 + blocknote->kol * 48;
			break;
		}
		sdvig = sdvig + 326 + blocknote->kol * 48;
	}

	return new_key_data;
}