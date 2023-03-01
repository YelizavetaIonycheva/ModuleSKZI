#ifndef _GOST28147_H_
#define _GOST28147_H_

#ifdef __cplusplus
extern "C" {
#endif

__attribute__((optnone)) void gost_zam_enc(unsigned int *n,unsigned int *k);
__attribute__((optnone)) void gost_zam_imz(unsigned int *n,unsigned int *k);
__attribute__((optnone)) void  gost_elem(unsigned int *n1,unsigned int *n2,unsigned int *ki) ;
/**************************************************************/
//Переменные и массивы
/**************************************************************/
//extern unsigned char Table[8][16];
//extern unsigned int M[4];

/**************************************************************/
//Константы
/**************************************************************/
#define GAMMIROVANIE_OS_REG	0x3				//режим гаммирование с ОС
#define MAKE_IMZ			0x4				//режим выработки ИМЗ

#define ENCRYPT				0x1				//шифрование
#define DECRYPT				0x2				//расшифрование

//#define TR_NO				0x0				//не использовать промежуточное состояние
//#define TR_YES				0x1				//использовать промежуточное состояние

#define LEN_IMZ_4			4				// Длина имитозащиты 8 байт
#define LEN_IMZ_8			8				// Длина имитозащиты 4 байта

#define SIZE_CRIPT_BLOCK	8				// Размер блока шифрования

#define SIZE_KEY			32				// Размер ключа в байтах
/**************************************************************/
//Основная структура
/**************************************************************/

typedef struct {
	unsigned short REGIM;					//выбор режима работы криптоалгоритма
	unsigned short CRYPT;					//выбор направления (шифрование/расшифрование)
	unsigned int * Sp;						//указатель на начальное заполнение (синхропосылка)
	unsigned int * Key;					//указатель на ключ (256 бит)
	unsigned char * Tz;						//указатель на таблицу подстановок
	unsigned char * Din;					//указатель на исходные данные
	unsigned char * Dout;					//указатель на результат
    int LenBytes;							//длина исходных данных в байтах
	unsigned short TR_STATE;				//работа с промежуточным состоянием
	unsigned char LenIMZ;					//Длина имитозащиты 4 или 8 байт
} GostStruct;

extern unsigned int KEY[SIZE_KEY];
extern unsigned char TABLE[8][16];

/*************************************************************/
//Прототипы функций
/**************************************************************/
__attribute__((optnone)) unsigned short Gost28147(GostStruct * Data);

__attribute__((optnone)) void saveTZ(unsigned char * TZ);

#ifdef __cplusplus
}
#endif
#endif