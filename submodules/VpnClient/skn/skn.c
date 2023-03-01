#include <stdlib.h>
#include <string.h>

#include "skn.h"

keylist_t compr_keylist;

void set_skn_keys(unsigned char * data, int len_data) {
	int size_keys;
	
	if(data == NULL || len_data == 0)
		return;
	
	size_keys = len_data - sizeof(compr_keylist.numEntries) - sizeof(compr_keylist.crc) - sizeof(compr_keylist.reserv);
	if(compr_keylist.keyEntry != NULL)
		free(compr_keylist.keyEntry);
	memset((unsigned char *)&compr_keylist, 0, sizeof(compr_keylist));
	compr_keylist.keyEntry = (keylist_entry_t*)malloc(size_keys);
	memcpy((unsigned char *)compr_keylist.keyEntry, data, size_keys);
	
	compr_keylist.numEntries 	= *(unsigned int *)(data + size_keys);
	compr_keylist.crc			= *(unsigned int *)(data + size_keys + 4);
	memcpy(compr_keylist.reserv, data + size_keys + 8, 24);
}

/*
 * Функция проверки ключа
 * Возвращает 0 если ключ разрешен в использовании
 */

unsigned char check_key(unsigned char *name, int len_name, unsigned char * serial, int len_serial, unsigned short kompl) {
	
	if(name == NULL || len_name <= 0 || len_name > 8)
		return 1;
	if(serial == NULL || len_serial <= 0 || len_serial > 8)
		return 1;
	
	for(int i = 0; i < compr_keylist.numEntries; i++) {
		if(memcmp(name, compr_keylist.keyEntry[i].name, len_name) && memcmp(serial, compr_keylist.keyEntry[i].serial, len_serial) && kompl == compr_keylist.keyEntry[i].kompl)
			return 1;
	}
	
	return 0;
}

unsigned int get_crc_skn_keys(void) {
	return compr_keylist.crc;
}

