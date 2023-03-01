#ifndef __SKN_H
#define __SKN_H

// Запись списка СКН
typedef struct
{
  unsigned char   name[8];              // Наименование
  unsigned char   serial[8];            // Номер серии
  unsigned short  kompl;                // Номер комплекта ключевого блокнота
  unsigned char   reserv[14];
} keylist_entry_t;

// Структура записей СКН
typedef struct {
  keylist_entry_t * keyEntry;
  unsigned int   	numEntries;
  unsigned int   	crc;
  unsigned char   	reserv[24];
} keylist_t;

void set_skn_keys(unsigned char * data, int len_data);
unsigned char check_key(unsigned char *name, int len_name, unsigned char * serial, int len_serial, unsigned short kompl);
unsigned int get_crc_skn_keys(void);

#endif
