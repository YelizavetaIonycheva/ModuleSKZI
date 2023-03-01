#include <string.h>
#include <malloc.h>
#include "cypher_magma.h"

unsigned int KEY[SIZE_KEY];
//----------------------------------------------------------
//Таблица подстановки
static const unsigned char p[8][16] =
{
	{0xc, 0x4, 0x6, 0x2, 0xa, 0x5, 0xb, 0x9, 0xe, 0x8, 0xd, 0x7, 0x0, 0x3, 0xf, 0x1},
    {0x6, 0x8, 0x2, 0x3, 0x9, 0xa, 0x5, 0xc, 0x1, 0xe, 0x4, 0x7, 0xb, 0xd, 0x0, 0xf},
    {0xb, 0x3, 0x5, 0x8, 0x2, 0xf, 0xa, 0xd, 0xe, 0x1, 0x7, 0x4, 0xc, 0x9, 0x6, 0x0},
    {0xc, 0x8, 0x2, 0x1, 0xd, 0x4, 0xf, 0x6, 0x7, 0x0, 0xa, 0x5, 0x3, 0xe, 0x9, 0xb},
    {0x7, 0xf, 0x5, 0xa, 0x8, 0x1, 0x6, 0xd, 0x0, 0x9, 0x3, 0xe, 0xb, 0x4, 0x2, 0xc},
    {0x5, 0xd, 0xf, 0x6, 0x9, 0x2, 0xc, 0xa, 0xb, 0x7, 0x8, 0x1, 0x4, 0x3, 0xe, 0x0},
    {0x8, 0xe, 0x2, 0x5, 0x6, 0x9, 0x1, 0xc, 0xf, 0x4, 0xb, 0x0, 0xd, 0xa, 0x3, 0x7},
    {0x1, 0x7, 0xe, 0xd, 0x0, 0x5, 0x8, 0x3, 0x4, 0xf, 0xa, 0x6, 0x9, 0xc, 0xb, 0x2}
};

//Используемый байт ключа при шифровании
static unsigned char kEncRoundKey[32] =
{
     0, 4, 8, 12, 16, 20, 24, 28, 0, 4, 8, 12, 16, 20, 24, 28, 0, 4, 8, 12, 16, 20, 24, 28, 28, 24, 20, 16, 12, 8, 4, 0
};

//Используемый байт ключа при расшифровании
static unsigned char kDecRoundKey[32] =
{
     0, 4, 8, 12, 16, 20, 24, 28, 28, 24, 20, 16, 12, 8, 4, 0, 28, 24, 20, 16, 12, 8, 4, 0, 28, 24, 20, 16, 12, 8, 4, 0
};

//Преобразование массива в int
static unsigned int uint8ToUint32(unsigned char* input)
{
	//unsigned int r = ((input[3]) | (input[2] << 8) | (input[1] << 16) | (input[0] << 24)); 	//BigEndian
	unsigned int r = ((input[0]) | (input[1] << 8) | (input[2] << 16) | (input[3] << 24)); 		//LittleEndian
	return r;
}

//Преобразование int в массив
static void uint32ToUint8(unsigned int input, unsigned char* output)
{
	int i;

	/*for(i = 0; i < 4; ++i)
		output[3 - i] = ((input >> (8 * i)) & 0x000000ff);*///BigEndian
	for(i = 0; i < 4; ++i)
		output[i] = ((input >> (8 * i)) & 0x000000ff);//LittleEndian
}

//Преобразование t
unsigned int funcT(unsigned int a)
{
	unsigned int res = 0;

	res ^=   p[ 0 ][ a & 0x0000000f ];
	res ^= ( p[ 1 ][ ( ( a & 0x000000f0 ) >>  4 ) ] << 4 );
	res ^= ( p[ 2 ][ ( ( a & 0x00000f00 ) >>  8 ) ] << 8 );
	res ^= ( p[ 3 ][ ( ( a & 0x0000f000 ) >> 12 ) ] << 12 );
	res ^= ( p[ 4 ][ ( ( a & 0x000f0000 ) >> 16 ) ] << 16 );
	res ^= ( p[ 5 ][ ( ( a & 0x00f00000 ) >> 20 ) ] << 20 );
	res ^= ( p[ 6 ][ ( ( a & 0x0f000000 ) >> 24 ) ] << 24 );
	res ^= ( p[ 7 ][ ( ( a & 0xf0000000 ) >> 28 ) ] << 28 );
	return res;
}

//Преобразование G
unsigned int funcG(unsigned int a, unsigned int k)
{
	unsigned int c = a + k;
	unsigned int tmp = funcT(c);
	unsigned int r = (tmp<<11) | (tmp >> 21);

	return r;
}

//Итерация
void Round(unsigned int* a1, unsigned int* a0, unsigned int k)
{
	unsigned int a;
	unsigned int tmp;

	a = *a0;
	tmp = funcG(*a0, k);

	*a0 = *a1 ^ tmp;
	*a1 = a;
}

//Заключительное преобразование после 32-х итераций
void RoundShtrih(unsigned int* a1, unsigned int* a0, unsigned int k)
{
	unsigned int tmp;

	tmp = funcG(*a0, k);
	*a1 ^= tmp;
}

//Преобразование блока 64 бита
void CryptBlock(unsigned char* input, unsigned char* output, unsigned char* key, unsigned char* keyIndex)
{
	unsigned int a1 = uint8ToUint32(input + 4);
	unsigned int a0 = uint8ToUint32(input);
	//unsigned int a1 = uint8ToUint32(input);
	//unsigned int a0 = uint8ToUint32(input+4);
	int i;

	for(i = 0; i < 31; ++i)
		Round(&a1, &a0, uint8ToUint32(key + keyIndex[i]));
	RoundShtrih(&a1, &a0, uint8ToUint32(key + keyIndex[31]));
	uint32ToUint8(a1, output+4);
	uint32ToUint8(a0, output);
	//uint32ToUint8(a1, output);
	//uint32ToUint8(a0, output+4);
}

//Шифрование
void EncryptMagma(unsigned char* input, unsigned char* output, unsigned char* key)
{
	CryptBlock(input, output, key, kEncRoundKey);
}

//Расшифрование
void DecryptMagma(unsigned char* input, unsigned char* output, unsigned char* key)
{
	CryptBlock(input, output, key, kDecRoundKey);
}
//----------------------------------------------------------

