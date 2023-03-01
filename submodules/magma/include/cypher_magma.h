#ifndef CYPHER_MAGMA_H_
#define CYPHER_MAGMA_H_

#ifdef __cplusplus
extern "C" {
#endif

//Размер блока алгоритма "Магма" в байтах
#define kBlockLen89		    8
#define LEN_IMZ_4			4				// Длина имитозащиты 4 байта
#define LEN_IMZ_8			8				// Длина имитозащиты 8 байт
#define LEN_SP_8            8               // Длина синхропосылки 8 байт
#define LEN_SP_4            4               // Длина синхропосылки 4 байта
#define LEN_LEN             4               // Длина поля ДЛИНА 4 байта
#define SIZE_CRYPT_BLOCK	8				// Размер блока шифрования
#define SIZE_KEY			32				// Размер ключа в байтах
//Размер ключа в байтах
#define kKeyLen89 		32

extern unsigned int KEY[SIZE_KEY];
extern unsigned char TABLE[8][16];

unsigned int funcT(unsigned int a);
unsigned int funcG(unsigned int a, unsigned int k);
void Round(unsigned int* a1, unsigned int* a0, unsigned int k);
void RoundShtrih(unsigned int* a1, unsigned int* a0, unsigned int k);
void CryptBlock(unsigned char* input, unsigned char* output, unsigned char* key, unsigned char* keyIndex);
void EncryptMagma(unsigned char* input, unsigned char* output, unsigned char* key);
void DecryptMagma(unsigned char* input, unsigned char* output, unsigned char* key);

#ifdef __cplusplus
}
#endif

#endif
