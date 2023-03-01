#include "cypher.h"
#include <string.h>
#include <malloc.h>

static void IncrementModulo(unsigned char* value, unsigned int size)
{
	unsigned int lastIndex = size - 1;
	unsigned int i;

	for(i = 0; i < size; ++i)
	{
		if( value[lastIndex - i] > 0xfe )
			value[lastIndex - i] -= 0xff;
		else
		{
			++value[lastIndex - i];
			break;
		}
	}
}

static void PackBlock(unsigned char* a, unsigned int aLen, unsigned char* b, unsigned char* r, unsigned int rLen)
{
	memcpy(r, a, aLen);
	memcpy(r + aLen, b, rLen - aLen);
}

static void ShifttLeftOne(unsigned char *r, unsigned int length)
{
	unsigned int i;
	unsigned char bitCur = 0, bitLast = 0;
	/*for(i = 0; i < length -1 ; ++i)
	{
		r[i] <<= 1;
		r[i] &= 0xfe;
		r[i] |= ((r[i+1]>>7)&0x1);
	}

	r[length -1] <<= 1;
	r[length -1] &= 0xfe;*/ //BigEndian

	for(i = 0; i < length; ++i)  //LittleEndian
	{
		//bitCur = GOST_MSB1(r[i]);
		bitCur =  (r[i] >> 7) & 0x01;
		r[i] <<= 1;
		r[i] &= 0xfe;
		r[i] ^= bitLast;
		bitLast = bitCur;
	}
}

static int ExpandImitKey(unsigned char *key, void *ctx)
{
	Context_imit* context;

	int r;
	unsigned int i;

	if(!ctx || !key)
		return 0;

	context = (Context_imit*)ctx;

	memset(context->tmpblock, 0, context->BlockLen);

	context->EncryptFunc(context->tmpblock, context->R, context->Keys);

	//r = ((context->R[0] & 0x80) == 0x80);// BigEndian
	r = ((context->R[7] & 0x80) == 0x80);// LittleEndian

	ShifttLeftOne(context->R, context->BlockLen);

	if(r == 1)
	{
		for(i = 0; i < context->BlockLen; ++i)
			context->K1[i] = context->R[i] ^ context->B[i];
	}
	else
		memcpy(context->K1, context->R, context->BlockLen);

	memcpy(context->tmpblock, context->K1, context->BlockLen);

	ShifttLeftOne(context->tmpblock, context->BlockLen);

	//if((context->K1[0] & 0x80) == 0x80)	// BigEndian
	if((context->K1[7] & 0x80) == 0x80)		// LittleEndian
	{
		for(i = 0; i < context->BlockLen; ++i)
			context->K2[i] = context->tmpblock[i] ^ context->B[i];
	}
	else
		memcpy(context->K2, context->tmpblock, context->BlockLen);
     return 1;
}

static unsigned int padd(unsigned char *data, unsigned int length, unsigned int blockLen)
{
	unsigned int paddingLen;
	unsigned int i;

	paddingLen = blockLen - (length % blockLen);

	*(data+length) = 0x80;

	for(i = 1; i < paddingLen; ++i)
		data[length+i] = 0;

	return length + paddingLen;
}

unsigned int cypher_magma_init(unsigned char *key, void* ctx)
{
    Context_ecb* context;

    context = (Context_ecb*)ctx;

    context->Alg 		 = kAlg89;
    context->EncryptFunc = EncryptMagma;
    context->DecryptFunc = DecryptMagma;
    context->BlockLen 	 = kBlockLen89;

    context->Keys = (unsigned char*)malloc(kKeyLen89);
    if(!context->Keys )
    	return 0;
    memcpy(context->Keys, key, kKeyLen89);
	return 1;
}

unsigned int cypher_magma_ctr_init(unsigned char* key, unsigned char *iv, unsigned int s, void *ctx)
{
    Context_ctr* context;

    context = (Context_ctr*)ctx;

    context->Alg 		 = kAlg89;
    context->EncryptFunc = EncryptMagma;
    context->BlockLen 	 = kBlockLen89;
    context->S 			 = s;
    context->tmpblock 	 = (unsigned char*)malloc(kKeyLen89);
    context->Keys 		 = (unsigned char*)malloc(kKeyLen89);
    context->Counter 	 = (unsigned char*)malloc(kBlockLen89);

    if( !context->tmpblock || !context->Keys || !context->Counter )
    	return 0;

    memcpy(context->Keys, key, kKeyLen89);
    memset(context->Counter, 0, kBlockLen89);
    memcpy(context->Counter, iv, kBlockLen89/2);
    return 1;
}

unsigned int cypher_magma_ofb_init(unsigned char *key, void *ctx, unsigned int s, unsigned char *iv, unsigned int ivLength)
{
	Context_ofb* context;

    context = (Context_ofb*)ctx;

    context->Alg 		 = kAlg89;
    context->EncryptFunc = EncryptMagma;
    context->DecryptFunc = DecryptMagma;
    context->BlockLen 	 = kBlockLen89;
    context->IV 		 = (unsigned char*)malloc(ivLength);
    context->tmpblock 	 = (unsigned char*)malloc(kBlockLen89);
    context->nextIV 	 = (unsigned char*)malloc(ivLength);
    context->Keys 		 = (unsigned char*)malloc(kKeyLen89);
    if( !context->IV || !context->tmpblock || !context->nextIV || !context->Keys )
         return 0;

    memcpy(context->IV, iv, ivLength);

    context->M = ivLength;
    context->S = s;

    memcpy(context->Keys, key, kKeyLen89);
    return 1;
}

unsigned int cypher_magma_cfb_init(unsigned char *key, void *ctx, unsigned int s, unsigned char *iv, unsigned int ivLength)
{
    Context_cfb* context;

    context = (Context_cfb*)ctx;

    context->Alg 		 = kAlg89;
    context->EncryptFunc = EncryptMagma;
    context->DecryptFunc = DecryptMagma;
    context->BlockLen 	 = kBlockLen89;
    context->IV 		 = (unsigned char*)malloc(ivLength);
    context->tmpblock 	 = (unsigned char*)malloc(kBlockLen89);
    context->nextIV 	 = (unsigned char*)malloc(ivLength);
    context->Keys 		 = (unsigned char*)malloc(kKeyLen89);
    if( !context->IV || !context->tmpblock || !context->nextIV || !context->Keys )
    	return 0;
    memcpy(context->IV, iv, ivLength);

    context->M = ivLength;
    context->S = s;
    memcpy(context->Keys, key, kKeyLen89);
    return 1;
}

unsigned int cypher_magma_imit_init(unsigned char *key, unsigned int s, void *ctx)
{
    Context_imit* context;

    context = (Context_imit*)ctx;

    context->Alg 		 = kAlg89;
    context->EncryptFunc = EncryptMagma;
    context->BlockLen 	 = kBlockLen89;
    context->S 			 = s;
    context->Keys 		 = (unsigned char*)malloc(kKeyLen89);
    context->R 			 = (unsigned char*)malloc(kBlockLen89);
    context->B 			 = (unsigned char*)malloc(kBlockLen89);
    context->K1 		 = (unsigned char*)malloc(kBlockLen89);
    context->K2 		 = (unsigned char*)malloc(kBlockLen89);
    context->C 			 = (unsigned char*)malloc(kBlockLen89);
    context->LastBlock 	 = (unsigned char*)malloc(kBlockLen89);
    context->tmpblock 	 = (unsigned char*)malloc(kBlockLen89);
    context->resimit 	 = (unsigned char*)malloc(kBlockLen89);
    if( !context->Keys || !context->R || !context->B
         || !context->K1 || !context->K2 || !context->C
         || !context->LastBlock || !context->tmpblock || !context->resimit )
         return 0;

    memcpy(context->Keys, key, kKeyLen89);
    memset(context->R, 0, kBlockLen89);
    memset(context->B, 0, kBlockLen89);
    //context->B[kBlockLen89-1] = 0x1B; //BigEndian
	context->B[0] = 0x1B; //LitleEndian

    memset(context->K1, 0, kBlockLen89);
    memset(context->K2, 0, kBlockLen89);
    memset(context->C, 0, kBlockLen89);
    memset(context->LastBlock, 0, kBlockLen89);

    context->LastBlockSize = 0;
    context->isFistBlock = 1;
    ExpandImitKey(key, ctx);
    return 1;
}

unsigned int cypher_encr_ecb(void *ctx, unsigned char *indata, unsigned char *outdata, unsigned int length)
{
	Context_ecb* context;
	unsigned char* block;
	unsigned int i;

	context = (Context_ecb*)ctx;

	if(!length || (length % context->BlockLen))
		return 0;
	block = outdata;
    for(i = 0; i < (length / context->BlockLen) ; ++i)
    {
         context->EncryptFunc(indata, block, context->Keys);
         indata += context->BlockLen;
         block += context->BlockLen;
    }
	return 1;
}

unsigned int cypher_decr_ecb(void *ctx, unsigned char *indata, unsigned char *outdata, unsigned int length)
{
	Context_ecb* context;
    unsigned int i;

    if(!ctx || !indata || !outdata)
    	return 0;

    context = (Context_ecb*)ctx;

    if(!length || (length % context->BlockLen))
    	return 0;

    for(i = 0; i < (length / context->BlockLen) ; ++i)
    {
    	context->DecryptFunc(indata, outdata, context->Keys);
    	indata += context->BlockLen;
    	outdata += context->BlockLen;
    }
    return 1;
}

unsigned int cypher_encr_ctr(void *ctx, unsigned char *indata, unsigned char *outdata, unsigned int length)
{
	Context_ctr* context;
    unsigned int i, j;

    if(!indata || !outdata || !ctx || !length)
    	return 0;

    context = (Context_ctr*)ctx;

    if( context->S == 0)
    	return 0;

    for(i = 0; i < (length / context->S); ++i)
    {
    	context->EncryptFunc(context->Counter, context->tmpblock, context->Keys);
    	for(j = 0; j < context->S; ++j)
    		outdata[j] = indata[j] ^ context->tmpblock[j];
    	outdata+= context->S;
    	indata+= context->S;
    	IncrementModulo(context->Counter, context->BlockLen);
    }

    if( (length % context->S) != 0 )
    {
    	context->EncryptFunc(context->Counter, &context->tmpblock[0], context->Keys);

    	for(j = 0; j < (length % context->S); ++j)
    		outdata[j] = indata[j] ^ context->tmpblock[j];
    	IncrementModulo(context->Counter, context->BlockLen);
    	context->S = 0;
    }
    return 1;
}

unsigned int cypher_encr_ofb(void *ctx, unsigned char *indata, unsigned char *outdata, unsigned int length)
{
    Context_ofb* context;
    unsigned int i, j;

    context = (Context_ofb*)ctx;

    if(context->S == 0 )
    	return 0;

    for(i = 0; i < ( length / context->BlockLen ); ++i)
    {
    	context->EncryptFunc(context->IV, context->tmpblock, context->Keys);

       	PackBlock(context->IV + context->BlockLen, context->M - context->BlockLen, context->tmpblock, context->nextIV, context->M);
       	memcpy(context->IV, context->nextIV, context->M);

       	for(j = 0; j < context->S; ++j)
       		*outdata++ = *indata++ ^ context->tmpblock[j];
    }

    if( ( length % context->BlockLen ) != 0 )
    {
    	context->EncryptFunc(context->IV, context->tmpblock, context->Keys);

    	PackBlock(context->IV + context->BlockLen, context->M - context->BlockLen, context->tmpblock, context->nextIV, context->M);
    	memcpy(context->IV, context->nextIV, context->M);

    	for(j = 0; j < length % context->BlockLen; ++j)
    		*outdata++ = *indata++ ^ context->tmpblock[j];
    	context->S = 0;
    }
	return 1;
}

unsigned int cypher_encr_cfb(void *ctx, unsigned char *indata, unsigned char *outdata, unsigned int length)
{
    Context_cfb* context;
    unsigned int i, j;

    context = (Context_cfb*)ctx;

    if( context->S == 0 )
    	return 0;

    for(i = 0; i < (length / context->S); ++i)
    {
    	context->EncryptFunc(context->IV, context->tmpblock, context->Keys);
       	for(j = 0; j < context->S; ++j)
       		outdata[j] = indata[j] ^ context->tmpblock[j];

       	indata += context->S;

       	PackBlock(context->IV + context->S, context->M - context->S, outdata, context->nextIV, context->M);
       	memcpy(context->IV, context->nextIV, context->M);
       	outdata += context->S;
    }

    if( (length % context->S) != 0 )
    {
    	context->EncryptFunc(context->IV, context->tmpblock, context->Keys);
    	for(j = 0; j < length % context->S; ++j)
    		outdata[j] = indata[j] ^ context->tmpblock[j];
    	context->S = 0;
    }
    return 1;
}

unsigned int cypher_decr_cfb(void *ctx, unsigned char *indata, unsigned char *outdata, unsigned int length)
{
	Context_cfb* context;
	unsigned int i, j;

	context = (Context_cfb*)ctx;

	if( context->S == 0 )
		return 0;

	for(i = 0; i < (length / context->S); ++i)
	{
		context->EncryptFunc(context->IV, context->tmpblock, context->Keys);

		for(j = 0; j < context->S; ++j)
			outdata[j] = indata[j] ^ context->tmpblock[j];
		outdata += context->S;

		PackBlock(context->IV + context->S, context->M - context->S, indata, context->nextIV, context->M);
		indata += context->S;
		memcpy(context->IV, context->nextIV, context->M);
	}

	if( (length % context->S) != 0 )
	{
		context->EncryptFunc(context->IV, context->tmpblock, context->Keys);
		for(j = 0; j < length % context->S; ++j)
			outdata[j] = indata[j] ^ context->tmpblock[j];
		context->S = 0;
	}
	return 1;
}

unsigned int cypher_imit(void *ctx, unsigned char *indata, unsigned char *outText, unsigned int length)
{
	Context_imit* context;
    unsigned int i, j;

    context = (Context_imit*)ctx;

    if( length < context->BlockLen )
    {
    	memcpy(context->LastBlock, indata, length);
    	context->LastBlockSize = length;
    	return 0;
    }

    for(i = 0; i < length / context->BlockLen; ++i)
    {
    	if(context->isFistBlock)
    	{
    		memcpy(context->LastBlock, indata, context->BlockLen);
    		context->LastBlockSize = context->BlockLen;
    		context->isFistBlock = 0;
    		indata += context->BlockLen;
    		continue;
    	}

    	for(j = 0; j < context->BlockLen; ++j)
    		context->LastBlock[j] ^= context->C[j];

    	context->EncryptFunc(context->LastBlock, context->C, context->Keys);
    	memcpy(context->LastBlock, indata, context->BlockLen);
    	indata += context->BlockLen;
    }

    if( length % context->BlockLen != 0 )
    {
    	for(j = 0; j < context->BlockLen; ++j)
    		context->LastBlock[j] ^= context->C[j];

    	context->EncryptFunc(context->LastBlock, context->C, context->Keys);
    	memcpy(context->LastBlock, indata, length % context->BlockLen);
    	context->LastBlockSize = length % context->BlockLen;
    }

    done_imit(context, outText);

    return 1;
}

void done_imit(void *ctx, unsigned char *value)
{
	Context_imit* context;
	unsigned char* K;
	unsigned int i;

	context = (Context_imit*)(ctx);

	memcpy(context->tmpblock, context->LastBlock, context->LastBlockSize);

	if(context->LastBlockSize!=context->BlockLen)
		padd(context->tmpblock, context->LastBlockSize, context->BlockLen);

	for(i = 0; i < context->BlockLen; ++i)
		context->tmpblock[i] ^=  context->C[i];

	K = context->LastBlockSize!=context->BlockLen ? context->K2 : context->K1;

    for(i = 0; i < context->BlockLen; ++i)
    	context->tmpblock[i] ^=  K[i];

    context->EncryptFunc(context->tmpblock, context->resimit, context->Keys);

    if(context->S == 8)
    	memcpy(value, context->resimit, context->S);
    else
		memcpy(value, context->resimit+4, context->S);
}

void free_ecb(void* ctx)
{
	Context_ecb* context;

    if(!ctx)
    	return;

    context = (Context_ecb*)(ctx);

    if(context->Keys)
    {
    	free(context->Keys);
    	context->Keys = 0;
    }
}

void free_ctr(void* ctx)
{
	Context_ctr* context;

	if(!ctx)
		return;

	context = (Context_ctr*)ctx;

	if(context->Keys)
	{
		free(context->Keys);
		context->Keys = 0;
	}

	if(context->Counter)
	{
		free(context->Counter);
		context->Counter = 0;
	}

	if(context->tmpblock)
	{
		free(context->tmpblock);
		context->tmpblock = 0;
	}
}

void free_ofb(void* ctx)
{
	Context_ofb* context;

	if(!ctx)
		return;

	context = (Context_ofb*)ctx;

	if(context->Keys)
	{
		free(context->Keys);
		context->Keys = 0;
	}

	if(context->IV)
	{
		free(context->IV);
		context->IV = 0;
	}

	if(context->tmpblock)
	{
		free(context->tmpblock);
		context->tmpblock = 0;
	}

	if(context->nextIV)
	{
		free(context->nextIV);
		context->nextIV = 0;
	}
}

void free_cfb(void* ctx)
{
	Context_cfb* context;

	if(!ctx)
		return;

	context = (Context_cfb*)ctx;

	if(context->Keys)
	{
		free(context->Keys);
		context->Keys = 0;
	}

	if(context->IV)
	{
		free(context->IV);
		context->IV = 0;
	}

	if(context->tmpblock)
	{
		free(context->tmpblock);
		context->tmpblock = 0;
	}

	if(context->nextIV)
	{
		free(context->nextIV);
		context->nextIV = 0;
	}
}

void free_imit(void* ctx)
{
	Context_imit* context;

	if(!ctx)
		return;

	context = (Context_imit*)ctx;

	if(context->Keys)
	{
		free(context->Keys);
		context->Keys = 0;
	}

	if(context->R)
	{
		free(context->R);
		context->R = 0;
	}

	if(context->B)
	{
		free(context->B);
		context->B = 0;
	}

	if(context->K1)
	{
		free(context->K1);
		context->K1 = 0;
	}

	if(context->K2)
	{
		free(context->K2);
		context->K2 = 0;
	}

	if(context->C)
	{
		free(context->C);
		context->C = 0;
	}

	if(context->LastBlock)
	{
		free(context->LastBlock);
		context->LastBlock = 0;
	}

	if(context->tmpblock)
	{
		free(context->tmpblock);
		context->tmpblock = 0;
	}

	if(context->resimit)
	{
		free(context->resimit);
		context->resimit = 0;
	}
}





