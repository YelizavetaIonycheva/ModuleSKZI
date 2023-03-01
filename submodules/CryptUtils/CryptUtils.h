#ifndef KEY_H_
#define KEY_H_

//структура описателя ключа
typedef struct key 
  {
  unsigned char   name[8];              // Наименование
  unsigned char   serial[8];            // Номер серии
  unsigned short  kompl;                // Номер комплекта ключевого блокнота 
  unsigned short  kol;                  // Количество комплектов в серии 
  unsigned char   date_begin[3];        // Дата начала действия комплекта
  unsigned char   date_end[3];          // Дата конца действия комплекта
  unsigned short  state;                // Статус: 0 - не загружен; 1 - загружен; 2 - не прошел проверку; 3 - загружен не полностью (ключ или маска)
  unsigned char   index_kb;             // Индекс ключевго блокнота
  unsigned char   index_s_box;          // Индекс узлов замены
  unsigned char   reserv[34];
  } KEY_portal;
  
 //структура описателя блокнота
typedef struct blocknote
  {
  unsigned char   	crc[4];
  unsigned char   	name[4];              // Наименование
  unsigned char   	serial[4];            // Номер серии
  unsigned short  	kompl;                // Номер комплекта ключевого блокнота 
  unsigned short  	kol;                  // Количество комплектов в серии 
  unsigned char   	crc1[4];
  unsigned short  	N2;
  unsigned char   	reserv[10]; 
  unsigned char   	key_hr[32]; 
  unsigned char   	key_dsch[32];  
  unsigned char   	table[64];
  } BLOCKNOTE;

void init_key_block(unsigned char * key, unsigned int len_key);

unsigned char * crypt_data_block(int is_first, unsigned char *data, int len_data, unsigned char *sp);

unsigned char * decrypt_data_block(int is_first, unsigned char *data, int len_data, unsigned char *sp);

unsigned char * getIZV();

void init_crypt_sound(unsigned char * key_out, unsigned char * key_in, unsigned char isCript);

unsigned char * crypt_sound(unsigned char * data, int len_data, int * len_close_data);

unsigned char * decrypt_sound(unsigned char * data, int len_data, int * len_open_data);

unsigned char * decrypt_data(unsigned char * crypted_data, int len_crypted_data, unsigned char * key, int len_key, int * len_open_data);

unsigned char * crypt_data(unsigned char *open_data, int len_open_data,
                           unsigned char *key, int len_key, int *len_crypted_data);

__attribute__((optnone)) unsigned char * decrypt_kompl_keys(unsigned char *crypted_kompl_keys, int len_crypted_kompl_keys);

//unsigned char * search_and_delete_key(unsigned char * key_delete, int len_key_delete, unsigned char * key_data, int len_key_data, int * len_new_keys);
//
//unsigned char * check_key_for_skn(unsigned char * key_data, int len_keys, int * len_new_keys);
//
//unsigned char * search_and_edit_key(unsigned char * key_edit, int len_key_edit, unsigned char * key_data, int len_key_data);
//
//unsigned char * add_key(unsigned char * key_edit, int len_key_edit, unsigned char * add_key_data, int len_add_key_data, unsigned char * old_key_data, int len_old_key_data, int * len_new_keys);
//
//unsigned char * check_key_date(unsigned char * key_data, int len_key_data, unsigned char * now_date, int len_now_date, int * len_new_key_data);

unsigned char * calculation_hash(unsigned char * data, int len_data);

unsigned char * hmac512(unsigned char * kbuf, int len_kbuf, unsigned char * tbuf, int len_tbuf);

//unsigned char * set_next_key_as_work(unsigned char * key_data, int len_key_data, unsigned char * next_key, int len_next_key, int * len_new_keys);

unsigned char * crypt(unsigned char * data, unsigned int len_data, unsigned char * key, unsigned int len_key, unsigned int *len_crypted_data);

unsigned char * decrypt(unsigned char * data, unsigned int len_data, unsigned char * key, unsigned int len_key, unsigned int *len_decrypted_data);

#endif