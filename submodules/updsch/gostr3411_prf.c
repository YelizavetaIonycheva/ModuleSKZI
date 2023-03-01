#include <string.h>
#include "gostr3411_prf.h"

//--------------------------------------------------------------------
//Узлы замены
static unsigned char TZ[] = {
	/*0x4,0xA,0x9,0x2,0xD,0x8,0x0,0xE,0x6,0xB,0x1,0xC,0x7,0xF,0x5,0x3,
	0xE,0xB,0x4,0xC,0x6,0xD,0xF,0xA,0x2,0x3,0x8,0x1,0x0,0x7,0x5,0x9,
	0x5,0x8,0x1,0xD,0xA,0x3,0x4,0x2,0xE,0xF,0xC,0x7,0x6,0x0,0x9,0xB,
	0x7,0xD,0xA,0x1,0x0,0x8,0x9,0xF,0xE,0x4,0x6,0xC,0xB,0x2,0x5,0x3,
	0x6,0xC,0x7,0x1,0x5,0xF,0xD,0x8,0x4,0xA,0x9,0xE,0x0,0x3,0xB,0x2,
	0x4,0xB,0xA,0x0,0x7,0x2,0x1,0xD,0x3,0x6,0x8,0x5,0x9,0xC,0xF,0xE,
	0xD,0xB,0x4,0x1,0x3,0xF,0x5,0x9,0x0,0xA,0xE,0x7,0x6,0x8,0x2,0xC,
	0x1,0xF,0xD,0x0,0x5,0x7,0xA,0x4,0x9,0x2,0x3,0xE,0x6,0xB,0x8,0xC,*/

	0xa,0x4,0x5,0x6,0x8,0x1,0x3,0x7,0xd,0xc,0xe,0x0,0x9,0x2,0xb,0xf,
	0x5,0xf,0x4,0x0,0x2,0xD,0xb,0x9,0x1,0x7,0x6,0x3,0xc,0xe,0xa,0x8,
	0x7,0xf,0xc,0xe,0x9,0x4,0x1,0x0,0x3,0xb,0x5,0x2,0x6,0xa,0x8,0xd,
	0x4,0xa,0x7,0xc,0x0,0xf,0x2,0x8,0xe,0x1,0x6,0x5,0xd,0xb,0x9,0x3,
	0x7,0x6,0x4,0xb,0x9,0xc,0x2,0xa,0x1,0x8,0x0,0xe,0xf,0xd,0x3,0x5,
	0x7,0x6,0x2,0x4,0xD,0x9,0xf,0x0,0xa,0x1,0x5,0xb,0x8,0xe,0xc,0x3,
	0xD,0xe,0x4,0x1,0x7,0x0,0x5,0xa,0x3,0xc,0x8,0xf,0x6,0x2,0x9,0xb,
	0x1,0x3,0xa,0x9,0x5,0xb,0x4,0xf,0x8,0x6,0x7,0xe,0xd,0x0,0x2,0xc,
};

//32 - битовые накопители N1, N2 из ГОСТ28147-89
static unsigned int n1, n2;  
//Промежуточные результаты
static unsigned short Hs[16], I[17], S[17], L[17];
static unsigned char Table[8][16];

typedef struct
{
	unsigned char * data;				//исходные данные
	unsigned char * hesh;				//хэш на исходные данные
	unsigned int   size;				//размер исходных данных в байтах
} heshstruct;	 

//-----------------------------------------------------------------
//Сложение 2-х длинных чисел
//На входе:
//		- слагаемое 1
//		- размерность слагаемого 1 в словах
//		- слагаемое 2
//		- размерность слагаемого 2 в словах
//		- результат
//-----------------------------------------------------------------
static void Add(unsigned short *U, int IU, unsigned short *V, int IV, unsigned short *W)
{
	unsigned short *u, *v, k;
	unsigned int s;
	int lu, lv, j;

	if(IU >= IV)
	{
		//Слагаемое 1 длиннее 2-го
		u  = U;
		lu = IU;
		v  = V;
		lv = IV;
	}
	else
	{
		v  = U;
		lv = IU;
		u  = V;
		lu = IV;
	}
	for(k = j = 0; j < lv; j++)
	{
		s    = (unsigned int)*u++ + *v++ + k;
		*W++ = (unsigned short)s;
		//в k перенос из суммы 2-х предыдущих слов 
		k = (s >> 16) ? 1 : 0;
	}
	while(j++ < lu)
	{
		//Протаскивание "переноса" по более длинному слагаемому
		s    = (unsigned int)*u++ + k;
		*W++ = (unsigned short)s;
		k = (s >> 16) ? 1 : 0;
	}
	*W = k;
}

//-----------------------------------------------------------------
//Сложение по модулю 2
//-----------------------------------------------------------------
static void summod2(unsigned char *x, unsigned char *y, unsigned char *z)
{
	int i;

	for(i = 0; i < 32; i++)
	{
		z[i] = x[i] ^ y[i];
	}
}

//-----------------------------------------------------------------
//Перестановка байтов
//-----------------------------------------------------------------
static void P(unsigned char *w, unsigned char *key)
{
	int i, k;

	for(i = 0; i <= 3; i++)
	{
		for(k = 0; k < 8; k++)
		{
			key[i + 4 * k] = w[8 * i + k];
		}
	}
}

//-----------------------------------------------------------------
//Преобразование А(x) = (x1 + x2)|x4|x3|x2 
//-----------------------------------------------------------------
static void A(unsigned char *x)
{
	int i;
	unsigned char buf[8];

	for(i = 0; i < 8; i++)
	{
		buf[i] = x[i] ^ x[i + 8];
	}
	for(i = 0; i < 24; i++)
	{
		x[i] = x[i + 8];
	}
	for(i = 0; i < 8; i++)
	{
		x[i + 24] = buf[i];
	}
}

//-----------------------------------------------------------------
//Генерация ключей
//-----------------------------------------------------------------
static void g_key(unsigned char *m, unsigned char *h, unsigned char *k)
{
	unsigned char c[96], u[32], v[32], w[32];
	int i;

	for(i = 0; i < 96; i++)
	{
		c[i] = 0;
	}
	c[33] = c[35] = c[37] = c[39] = c[40] = c[42] = c[44] = c[46] = 0xFF;
	c[49] = c[50] = c[52] = c[55] = c[56] = c[60] = c[61] = c[63] = 0xFF;
	for(i = 0; i < 32; i++)
	{
		u[i] = h[i];
		v[i] = m[i];
	}
	//Сложение по модулю 2
	summod2(u, v , w);
	//Перестановка
	P(w, k);
	for(i = 0; i < 3; i++)
	{
		A(u);
		summod2(u, c + i * 32, u);
		A(v);
		A(v);
		summod2(u, v, w);
		P(w, k + 32 * (i + 1));
	}
}

//-----------------------------------------------------------------
//Итерация ГОСТ28147-89
//-----------------------------------------------------------------
static void gost_elem(unsigned int *n1,unsigned int *n2,unsigned int *ki)
{
	unsigned char r[4];
	
	*(unsigned int *)r = *n1 + *ki;									
	r[0] = (Table[1][(r[0] >> 4) & 0xf] << 4) | (Table[0][r[0] & 0xf]);
	r[1] = (Table[3][(r[1] >> 4) & 0xf] << 4) | (Table[2][r[1] & 0xf]);
	r[2] = (Table[5][(r[2] >> 4) & 0xf] << 4) | (Table[4][r[2] & 0xf]);
	r[3] = (Table[7][(r[3] >> 4) & 0xf] << 4) | (Table[6][r[3] & 0xf]);
	*n2 ^= (*(unsigned int *)r << 11) | ((*(unsigned int*)r >> 21) & 0x7FF);
	return;
}

//-----------------------------------------------------------------
//Простая замена и ГОСТ28147-89 (шифрование)
//-----------------------------------------------------------------
static void pz_z(unsigned int *x)
{
	unsigned int cur;

	gost_elem(&n1, &n2, x);
	gost_elem(&n2, &n1, x + 1);
	gost_elem(&n1, &n2, x + 2);
	gost_elem(&n2, &n1, x + 3);
	gost_elem(&n1, &n2, x + 4);
	gost_elem(&n2, &n1, x + 5);
	gost_elem(&n1, &n2, x + 6);
	gost_elem(&n2, &n1, x + 7);
	
	gost_elem(&n1, &n2, x);
	gost_elem(&n2, &n1, x + 1);
	gost_elem(&n1, &n2, x + 2);
	gost_elem(&n2, &n1, x + 3);
	gost_elem(&n1, &n2, x + 4);
	gost_elem(&n2, &n1, x + 5);
	gost_elem(&n1, &n2, x + 6);
	gost_elem(&n2, &n1, x + 7);
	
	gost_elem(&n1, &n2, x);
	gost_elem(&n2, &n1, x + 1);
	gost_elem(&n1, &n2, x + 2);
	gost_elem(&n2, &n1, x + 3);
	gost_elem(&n1, &n2, x + 4);
	gost_elem(&n2, &n1, x + 5);
	gost_elem(&n1, &n2, x + 6);
	gost_elem(&n2, &n1, x + 7);
	
	gost_elem(&n1, &n2, x + 7);
	gost_elem(&n2, &n1, x + 6);
	gost_elem(&n1, &n2, x + 5);
	gost_elem(&n2, &n1, x + 4);
	gost_elem(&n1, &n2, x + 3);
	gost_elem(&n2, &n1, x + 2);
	gost_elem(&n1, &n2, x + 1);
	gost_elem(&n2, &n1, x);

	cur = n1; 
	n1 = n2; 
	n2 = cur;
}

//-----------------------------------------------------------------
//Шифрующее преобразование
//-----------------------------------------------------------------
static void crypt(unsigned char *h, unsigned char *key, unsigned char *s)
{
	int i;
	unsigned int *k;

	for(i = 0; i < 4; i++)
	{
		k  = (unsigned int *)(h + i * 8);
		n1 = *k;
		n2 = *(k+1);
		k  = (unsigned int *)(key + 32 * i);
		pz_z(k);
		k = (unsigned int *)(s + i * 8);
		*k     = n1;
		*(k+1) = n2;
	}
}

//-----------------------------------------------------------------
//Перемешивающее преобразование
//-----------------------------------------------------------------
static void s_reg(unsigned short *r)
{
	r[16] = r[0] ^ r[1] ^ r[2] ^ r[3] ^ r[12] ^ r[15];
}

//-----------------------------------------------------------------
//Перемешивающее преобразование результата шифрования
//-----------------------------------------------------------------
static void reg(unsigned char *m, unsigned char *s, unsigned char *h)
{
	int i;
	
	for(i = 0; i < 12; i++)
	{
		s_reg((unsigned short *)(s + 2 * i));
	}
	summod2(s + 24, m, s + 24);
	s_reg((unsigned short *)(s + 24));
	summod2(s + 26, h, s + 26);
	for(i = 0; i < 61; i++)
	{
		s_reg((unsigned short *)(s + 26 + 2 * i));
	}
	for(i = 0; i < 32; i++)
	{
		h[i] = s[i + 148];
	}
}

//-----------------------------------------------------------------
//"Шаговая" функция хэширования
//-----------------------------------------------------------------
static void s_hash(unsigned char *m, unsigned char *h)
{
	unsigned short s[90];
	unsigned char key[128];

	//Генерация ключей
	g_key(m, h, key);
	//Шифрующее преобразование
	crypt(h, key, (unsigned char *)s);
	//Перемешивающее преобразование результата шифрования
	reg(m, (unsigned char *)s, h);
}

//Программная реализация алгоритма хэширования по ГОСТ 34.11-94
static void hesh341194(heshstruct *data)
{
	unsigned int i, j, nl, seti, end;
	unsigned short m[17];
	unsigned char H[32];

	//Преобразование таблицы подстановок
	nl = 0;
	for(i = 0; i < 8; i++)
	{
		for(j = 0; j < 16; j++)
			Table[i][j] = TZ[nl++];
	}
	//Загрузка стартового вектора хэширования	
	for(i = 0; i < 32; i++)
		H[i] = 0;	
	//Этап 1 пп. 1.3, 1.4
	for(i = 0; i < 16; i++)
	{
		I[i] = 0;
		S[i] = 0;
		L[i] = 0;
	}
	//Пп. 3.3
	L[0] = 256;
	
	seti = 0;
	end  = 0;
	//Обработка данных (по 256 бит)
	while(end == 0)
	{
		if(data->size - seti > 32)
		{
			for(i = 0; i < 32; i++)
				*((unsigned char *)m + i) = data->data[seti + i];
			nl    = 32;
			seti += 32;
		}
		else
		{
			for(i = 0; i < data->size - seti; i++)
				*((unsigned char *)m + i) = data->data[seti + i];
			nl  = data->size - seti;
			end = 1;	
		}
		//Дополнение 0-ми при неполном блоке
		for(i = nl; i < 32; i++)
			*((unsigned char *)m + i) = 0;
		//Определяем число прочитанных бит
		nl *= 8;
		//Корректировка для п. 2.2 этапа 2
		if(nl < 256)
		{
			L[0] = nl;
			L[1] = 0;
		}
		//Сложение
		Add(I, 16, L, 16, I);
		Add(S, 16, m, 16, S);
		//Вызов "шаговой" функции
		s_hash((unsigned char *)m, H);
	}
	for(i = 0; i < 32; i++)
		*((unsigned char *)Hs + i) = H[i];
	//Пп. 2.6, 2.7
	s_hash((unsigned char *)I, H);
	s_hash((unsigned char *)S, H);
	//Перепысиваем полученную хэш
	for(i = 0; i < 32; i++)
		data->hesh[i] = H[i];
}
//--------------------------------------------------------------------

static void hmac(unsigned char *K, unsigned char *D, int D_size, unsigned char *tmp)
{
	int i;
	unsigned char KK[64], buf[128], hesh[32];
	heshstruct data;

	memset(KK, 0, sizeof(KK));
	memcpy(KK, K, 32);
	for(i = 0; i < 32; i++)
		buf[i] = KK[i] ^ 0x36;
	memcpy(buf + 32, D, D_size);
	data.data = buf;
	data.hesh = hesh;
	data.size = 32 + D_size;
	hesh341194(&data);
	for(i = 0; i < 32; i++)
		buf[i] = KK[i] ^ 0x5C;
	memcpy(buf + 32, hesh, 32);
	data.hesh = tmp;
	data.size = 64;
	hesh341194(&data);
}

void gostr3411_prf(unsigned char *K, unsigned char *D, unsigned char *tmp)
{
	unsigned char A_1[64], A_2[64];
	
	//A(1)
	hmac(K, D, 32, A_1);
	//A(1) + seed
	memcpy(A_1 + 32, D, 32);
	//k1
	hmac(K, A_1, 64, tmp);

	//A(2)
	hmac(K, A_1, 32, A_2);
	//A(2) + seed
	memcpy(A_2 + 32, D, 32);
	//k2
	hmac(K, A_2, 64, tmp + 32);
}

