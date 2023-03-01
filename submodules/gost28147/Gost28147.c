#include "Gost28147.h"

unsigned char Table[8][16];
unsigned int M[4];

unsigned int KEY[SIZE_KEY];
unsigned char TABLE[8][16]  = {
		0xC,0x4,0x6,0x2,0xA,0x5,0xB,0x9,0xE,0x8,0xD,0x7,0x0,0x3,0xF,0x1,			//узел замены МАГМА
		0x6,0x8,0x2,0x3,0x9,0xA,0x5,0xC,0x1,0xE,0x4,0x7,0xB,0xD,0x0,0xF,
		0xB,0x3,0x5,0x8,0x2,0xF,0xA,0xD,0xE,0x1,0x7,0x4,0xC,0x9,0x6,0x0,
		0xC,0x8,0x2,0x1,0xD,0x4,0xF,0x6,0x7,0x0,0xA,0x5,0x3,0xE,0x9,0xB,
		0x7,0xF,0x5,0xA,0x8,0x1,0x6,0xD,0x0,0x9,0x3,0xE,0xB,0x4,0x2,0xC,
		0x5,0xD,0xF,0x6,0x9,0x2,0xC,0xA,0xB,0x7,0x8,0x1,0x4,0x3,0xE,0x0,
		0x8,0xE,0x2,0x5,0x6,0x9,0x1,0xC,0xF,0x4,0xB,0x0,0xD,0xA,0x3,0x7,
		0x1,0x7,0xE,0xD,0x0,0x5,0x8,0x3,0x4,0xF,0xA,0x6,0x9,0xC,0xB,0x2,
};

#ifdef __cplusplus
extern "C" {
#endif

unsigned short Gost28147(GostStruct * Data)
{
    unsigned int D,E,N[2];
	if(!Data->LenBytes){return 0;}
    //Начальная инициализация
	N[0]=0;N[1]=0;
	int index = 0;
	for(int  i = 0; i < 8; i++) {
		for(int j = 0; j < 16; j++) {
			Table[i][j] = Data->Tz[index];
            index++;
		}
	}

	switch(Data->REGIM)
	{
	case GAMMIROVANIE_OS_REG:
		{
		if(Data->TR_STATE==TR_NO)
			{
			N[0]=Data->Sp[0];
			N[1]=Data->Sp[1];
			}
		else
			{
			N[0]=M[0];
			N[1]=M[1];
			}
		switch(Data->CRYPT)
			{
			case ENCRYPT:
				{
				while(1)
					{
					gost_zam_enc(N,Data->Key);
					Data->Dout[0]=(unsigned char)(N[0])^(Data->Din[0]);
					Data->LenBytes--;
					if(!Data->LenBytes){break;}
					Data->Dout[1]=(unsigned char)(N[0]>>8)^(Data->Din[1]);
					Data->LenBytes--;
					if(!Data->LenBytes){break;}
					Data->Dout[2]=(unsigned char)(N[0]>>16)^(Data->Din[2]);
					Data->LenBytes--;
					if(!Data->LenBytes){break;}
					Data->Dout[3]=(unsigned char)(N[0]>>24)^(Data->Din[3]);
					
					N[0]=*(unsigned int *)Data->Dout;
					Data->LenBytes--;
					if(!Data->LenBytes){break;}
			
					Data->Dout[4]=(unsigned char)(N[1])^(Data->Din[4]);
					Data->LenBytes--;
					if(!Data->LenBytes){break;}
					Data->Dout[5]=(unsigned char)(N[1]>>8)^(Data->Din[5]);
					Data->LenBytes--;
					if(!Data->LenBytes){break;}
					Data->Dout[6]=(unsigned char)(N[1]>>16)^(Data->Din[6]);
					Data->LenBytes--;
					if(!Data->LenBytes){break;}
					Data->Dout[7]=(unsigned char)(N[1]>>24)^(Data->Din[7]);
					
					N[1]=*(unsigned int *)(Data->Dout+4);
					Data->LenBytes--;
					if(!Data->LenBytes){break;}

					Data->Dout+=8;
					Data->Din+=8;
					}
				M[0]=N[0];M[1]=N[1];
				break;	
				}
			case DECRYPT:
				{
				while(1)
					{
					gost_zam_enc(N,Data->Key);
					D=*(unsigned int *)Data->Din;
					E=*(unsigned int *)(Data->Din+4);
					Data->Dout[0]=(unsigned char)(N[0])^(Data->Din[0]);
					Data->LenBytes--;
					if(!Data->LenBytes){break;}
					Data->Dout[1]=(unsigned char)(N[0]>>8)^(Data->Din[1]);
					Data->LenBytes--;
					if(!Data->LenBytes){break;}
					Data->Dout[2]=(unsigned char)(N[0]>>16)^(Data->Din[2]);
					Data->LenBytes--;
					if(!Data->LenBytes){break;}
					Data->Dout[3]=(unsigned char)(N[0]>>24)^(Data->Din[3]);
					
					N[0]=D;
					Data->LenBytes--;
					if(!Data->LenBytes){break;}
			
					Data->Dout[4]=(unsigned char)(N[1])^(Data->Din[4]);
					Data->LenBytes--;
					if(!Data->LenBytes){break;}
					Data->Dout[5]=(unsigned char)(N[1]>>8)^(Data->Din[5]);
					Data->LenBytes--;
					if(!Data->LenBytes){break;}
					Data->Dout[6]=(unsigned char)(N[1]>>16)^(Data->Din[6]);
					Data->LenBytes--;
					if(!Data->LenBytes){break;}
					Data->Dout[7]=(unsigned char)(N[1]>>24)^(Data->Din[7]);
					
					N[1]=E;
					Data->LenBytes--;
					if(!Data->LenBytes){break;}

					Data->Dout+=8;
					Data->Din+=8;
					}
				M[0]=N[0];M[1]=N[1];
				break;
				}
			default:return 0;
			}
		break;
		}

	case MAKE_IMZ:
		{
		if(Data->LenIMZ != LEN_IMZ_4 && Data->LenIMZ != LEN_IMZ_8)
			return 0;
		if(Data->TR_STATE==TR_NO)
			{
			N[0]=0;
			N[1]=0;
			}
		else
			{
				N[0]=M[0];
				N[1]=M[1];
			}
		while(Data->LenBytes>0) {
				N[0]^=*(unsigned int *)Data->Din;
				N[1]^=*(unsigned int *)(Data->Din+4);
				gost_zam_imz(N,Data->Key);
				Data->Din+=8;
				Data->LenBytes-=8;
			}
			*(unsigned int *)Data->Dout=N[0];
			if(Data->LenIMZ == LEN_IMZ_8) {
				*(unsigned int *)(Data->Dout+4)=N[1];
			}
		M[0]=N[0];M[1]=N[1];
		break;
		}
	
	default:return 0;
	}


	return 1;
}

void gost_zam_enc(unsigned int *n,unsigned int *k)
{
	unsigned int cur;
	
	gost_elem(n,n+1,k);
	gost_elem(n+1,n,k+1);
	gost_elem(n,n+1,k+2);
	gost_elem(n+1,n,k+3);
	gost_elem(n,n+1,k+4);
	gost_elem(n+1,n,k+5);
	gost_elem(n,n+1,k+6);
	gost_elem(n+1,n,k+7);

	gost_elem(n,n+1,k);
	gost_elem(n+1,n,k+1);
	gost_elem(n,n+1,k+2);
	gost_elem(n+1,n,k+3);
	gost_elem(n,n+1,k+4);
	gost_elem(n+1,n,k+5);
	gost_elem(n,n+1,k+6);
	gost_elem(n+1,n,k+7);

	gost_elem(n,n+1,k);
	gost_elem(n+1,n,k+1);
	gost_elem(n,n+1,k+2);
	gost_elem(n+1,n,k+3);
	gost_elem(n,n+1,k+4);
	gost_elem(n+1,n,k+5);
	gost_elem(n,n+1,k+6);
	gost_elem(n+1,n,k+7);

	gost_elem(n,n+1,k+7);
	gost_elem(n+1,n,k+6);
	gost_elem(n,n+1,k+5);
	gost_elem(n+1,n,k+4);
	gost_elem(n,n+1,k+3);
	gost_elem(n+1,n,k+2);
	gost_elem(n,n+1,k+1);
	gost_elem(n+1,n,k);

	cur=*n; 
	*n=*(n+1); 
	*(n+1)=cur;

	return;
}

//--------------------------------------------------------------------------
void gost_zam_imz(unsigned int *n,unsigned int *k)
{
	gost_elem(n,n+1,k);
    gost_elem(n+1,n,k+1);
	gost_elem(n,n+1,k+2);
	gost_elem(n+1,n,k+3);
	gost_elem(n,n+1,k+4);
	gost_elem(n+1,n,k+5);
	gost_elem(n,n+1,k+6);
	gost_elem(n+1,n,k+7);

	gost_elem(n,n+1,k);
	gost_elem(n+1,n,k+1);
	gost_elem(n,n+1,k+2);
	gost_elem(n+1,n,k+3);
	gost_elem(n,n+1,k+4);
	gost_elem(n+1,n,k+5);
	gost_elem(n,n+1,k+6);
	gost_elem(n+1,n,k+7);
    return;
}

void gost_elem(unsigned int *n1,unsigned int *n2,unsigned int *ki)		//итерация ГОСТ
{
	unsigned char r[4];
	*(unsigned int *)r=*n1+*ki;											//сложение с ключом по модулю 2^32
	r[0]=(Table[1][(r[0]>>4)&0xf]<<4)|(Table[0][r[0]&0xf]);
	r[1]=(Table[3][(r[1]>>4)&0xf]<<4)|(Table[2][r[1]&0xf]);
	r[2]=(Table[5][(r[2]>>4)&0xf]<<4)|(Table[4][r[2]&0xf]);
	r[3]=(Table[7][(r[3]>>4)&0xf]<<4)|(Table[6][r[3]&0xf]);
	*n2^=(*(unsigned int *)r<<11)|((*(unsigned int*)r>>21)&0x7FF);
    return;
}





#ifdef __cplusplus
}
#endif