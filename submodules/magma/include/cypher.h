#ifndef CYPHER_H_
#define CYPHER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "cypher_magma.h"


//Признак алгоритма "Магма"
#define kAlg89			2

//указатель на функцию шифрования
typedef void (*pEncrypt)(unsigned char* plainText, unsigned char* chipherText, unsigned char* keys);
//указатель на функцию расшифрования
typedef void (*pDecrypt)(unsigned char* chipherText, unsigned char* plainText, unsigned char* keys);

#define kEcb89ContextLen 	0x38

#define kCtr89ContextLen 	0x48

#define kOfb89ContextLen 	0x60

#define kCfb89ContextLen 	0x60

#define kImit89ContextLen 	0x88

//Контекст ECBs
typedef struct
{
	unsigned char Alg; /**< идентификатор алгоритма */
	unsigned char* Keys; /**< ключ */
	unsigned int BlockLen; /**< размер блока */
	pEncrypt EncryptFunc; /**< функция шифрования */
	pDecrypt DecryptFunc; /**< функция расшифрования */
} Context_ecb;

//Контекст CTR
typedef struct
{
	unsigned char Alg; /**< идентификатор алгоритма */
	unsigned char* Counter; /**< счетчик */
	unsigned char* Keys; /**< ключ */
	unsigned int S; /**< размер синхропосылки */
	unsigned int BlockLen;  /**< размер блока */
	pEncrypt EncryptFunc; /**< функция шифрования */
	unsigned char *tmpblock; /**< временный блок */
} Context_ctr;

//Контекст OFB
typedef struct
{
	unsigned char Alg; /**< идентификатор алгоритма */
	unsigned char* IV; /**< синхропосылка */
	unsigned char* Keys;  /**< ключ */
	unsigned int M; /**< размер синхрпосылки */
	unsigned int S; /**< параметр S */
	unsigned int BlockLen; /**< размер блока */
	pEncrypt EncryptFunc; /**< функция шифрования */
	pDecrypt DecryptFunc; /**< функция расшифрования */
	unsigned char *tmpblock;  /**< временный блок */
	unsigned char* nextIV; /**< синхропосылка для следующего блока */
} Context_ofb;

//Контекст CFB
typedef struct
{
	unsigned char Alg; /**< идентификатор алгоритма */
	unsigned char* IV; /**< синхропосылка */
	unsigned char* Keys; /**< ключ */
	unsigned int M; /**< размер синхрпосылки */
	unsigned int S; /**< параметр S */
	unsigned int BlockLen; /**< размер блока */
	pEncrypt EncryptFunc; /**< функция шифрования */
	pDecrypt DecryptFunc; /**< функция расшифрования */
	unsigned char *tmpblock; /**< временный блок */
	unsigned char* nextIV; /**< синхропосылка для следующего блока */
} Context_cfb;

//Контекст имитовставки
typedef struct
{
	unsigned char Alg; /**< идентификатор алгоритма */
	unsigned char* Keys; /**< ключ */
	unsigned char* K1; /**< вспомогательный параметр K1 */
	unsigned char* K2; /**< вспомогательный параметр K2 */
	unsigned char* B; /**< вспомогательный параметр B */
	unsigned char* R; /**< вспомогательный параметр R */
	unsigned char* C; /**< вспомогательный параметр C */
	unsigned char* LastBlock; /**< предыдущий блок */
	unsigned int S; /**< параметр S */
	unsigned int BlockLen; /**< размер блока */
	unsigned int LastBlockSize; /**< размер предыдущего блока */
	int isFistBlock; /**< идентификатор первого блока */
	pEncrypt EncryptFunc; /**< функция шифрования */
	unsigned char *tmpblock; /**< временный блок */
	unsigned char *resimit; /**< имитовставка */
} Context_imit;


unsigned int cypher_magma_init(unsigned char *key, void* ctx);
unsigned int cypher_magma_ctr_init(unsigned char* key, unsigned char *iv, unsigned int s, void *ctx);
unsigned int cypher_magma_ofb_init(unsigned char *key, void *ctx, unsigned int s, unsigned char *iv, unsigned int ivLength);
unsigned int cypher_magma_cfb_init(unsigned char *key, void *ctx, unsigned int s, unsigned char *iv, unsigned int ivLength);
unsigned int cypher_magma_imit_init(unsigned char *key, unsigned int s, void *ctx);
unsigned int cypher_encr_ecb(void *ctx, unsigned char *indata, unsigned char *outdata, unsigned int length);
unsigned int cypher_decr_ecb(void *ctx, unsigned char *indata, unsigned char *outdata, unsigned int length);
unsigned int cypher_encr_ctr(void *ctx, unsigned char *indata, unsigned char *outdata, unsigned int length);
unsigned int cypher_encr_ofb(void *ctx, unsigned char *indata, unsigned char *outdata, unsigned int length);
unsigned int cypher_encr_cfb(void *ctx, unsigned char *indata, unsigned char *outdata, unsigned int length);
unsigned int cypher_decr_cfb(void *ctx, unsigned char *indata, unsigned char *outdata, unsigned int length);
unsigned int cypher_imit(void *ctx, unsigned char *indata, unsigned char *outText, unsigned int length);
void done_imit(void *ctx, unsigned char *value);
void free_ecb(void* ctx);
void free_ctr(void* ctx);
void free_ofb(void* ctx);
void free_cfb(void* ctx);
void free_imit(void* ctx);

#ifdef __cplusplus
}
#endif

#endif

