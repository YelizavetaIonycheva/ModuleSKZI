#include "ecp_algebra.h"

//------------------------------------------------------
//Обмен координатами (если sm = 1)
//------------------------------------------------------
static void ECPswap(ECP_projective *P0,ECP_projective *P1,int sm)
{
	int tmp0, tmp1, i, *ecp[2], mask, smmask, mask1;
	
	ecp[0] = (int*)P0; 
	ecp[1] = (int*)P1;
	mask   = 0; 
	smmask = sm & 1;
	for(i = 0; i < sizeof(ECP_projective) / sizeof(int); i++)
	{
		mask1   = ecp[0][i] & 1;
		mask   ^= mask1;
		smmask ^= mask1;
		tmp0    = ecp[mask][i];
		tmp1    = ecp[mask ^ 1][i];
	    ecp[smmask][i]		= tmp0;
		ecp[smmask ^ 1][i]  = tmp1;
	}
}

//------------------------------------------------------
//Удвоение точки (P0 = 2P0)
//------------------------------------------------------
static void ECPsqr(ECP_projective *P0)
{
	residue T, S, U;
	
	Rmul(T, P0->Z, P0->Z, ECp);				//T=Z1*Z1
	Rmul(S, ECae, T, ECp); 
	Rmul(S, S, T, ECp);						//S=a*T*T
	Rmul(T, P0->X, P0->X, ECp);
	Radd(U, T, T, ECp);
	Radd(U, U, T, ECp);
	Radd(U, U, S, ECp);						//U=3(X1*X1)+S
	Rmul(T, P0->Y, P0->Y, ECp);
	Radd(T, T, T, ECp);						//T=2(Y1*Y1)
	Rmul(S, P0->X, T, ECp);
	Radd(S, S, S, ECp);						//S=2(X1*T)
	Rmul(P0->Z, P0->Z, P0->Y, ECp);
	Radd(P0->Z, P0->Z, P0->Z, ECp);			//Z2=2(Z1*Y1)
	Rmul(P0->X, U, U, ECp);
	Rsub(P0->X, P0->X, S, ECp);
	Rsub(P0->X, P0->X, S, ECp);				//X2=U*U-2S
	Rmul(T, T, T, ECp);						//T=T*T
	Rsub(S, S, P0->X, ECp);
	Rmul(P0->Y, U, S, ECp);
	Rsub(P0->Y, P0->Y, T, ECp);
	Rsub(P0->Y, P0->Y, T, ECp);				//Y2=U*(S-X2)-2T
}

//------------------------------------------------------
//Нахождение кратной точки (Ps = sP)
//------------------------------------------------------
void ECPpow(ECP_affine *Ps, ECP_affine *P, residue s)
{
	ECP_projective P0, P1;
	int m, sm;

	affine2projective(&P0, P);
	for(m = n - 1; ((s[m >> 4] >> (m & 15)) == 0) && (m > 0); m--);
	for(m--; m >= 0; m--)
    {
		sm = (s[m >> 4] >> (m & 15)) & 1;
        ECPsqr(&P0);
		ECPmul(&P1, &P0, P);
        ECPswap(&P0, &P1, sm);
    }
	projective2affine(Ps,&P0);
}

//------------------------------------------------------
//Определение проективных координат по аффинным
//------------------------------------------------------
void affine2projective(ECP_projective *Pp, ECP_affine *Pa)
{
	GF2MF(Pp->X, Pa->x, ECe2_p, ECp);
	GF2MF(Pp->Y, Pa->y, ECe2_p, ECp);
	Rcopy(Pp->Z, ECe_p);
}

//------------------------------------------------------
//Определение аффинных координат по проективным
//------------------------------------------------------
void projective2affine(ECP_affine *Pa, ECP_projective *Pp)
{
	residue Zinv;

	Rinv(Zinv,  Pp->Z, ECp);
	Rmul(Pa->x, Pp->X, Zinv, ECp);
	Rmul(Pa->x, Pa->x, Zinv, ECp);
	MF2GF(Pa->x, Pa->x, ECp);
	Rmul(Pa->y, Pp->Y, Zinv, ECp);
	Rmul(Pa->y, Pa->y, Zinv, ECp);
	Rmul(Pa->y, Pa->y, Zinv, ECp);
	MF2GF(Pa->y, Pa->y, ECp);
}

//------------------------------------------------------
//Сумма точек (P3 = P1 + P2)
//------------------------------------------------------
void ECPmul(ECP_projective *P3, ECP_projective *P1, ECP_affine *P2)
{
	residue T, S, TT, A, B, Z12, B12, B13;
	residue x2, y2;

	GF2MF(x2, P2->x, ECe2_p, ECp);
	GF2MF(y2, P2->y, ECe2_p, ECp);

	Rmul(Z12, P1->Z, P1->Z, ECp);				//Z1*Z1
	Rmul(T, Z12, P1->Z, ECp);					//Z1*Z1*Z1
	Rmul(S, T, y2, ECp);						//Z1*Z1*Z1*y2
	Rsub(A, S, P1->Y, ECp);						//A = Z1*Z1*Z1*y2-Y1

	Rmul(T, Z12, x2, ECp);						//Z1*Z1*x2
	Rsub(B, T, P1->X, ECp);						//B = Z1*Z1*x2-X1

	Rmul(B12, B, B, ECp);						//B*B
	Rmul(TT, P1->X, B12, ECp);					//X1*B*B
	Rmul(S, A, A, ECp);							//A*A
	Rmul(B13, B12, B, ECp);						//B*B*B
	Rsub(T, S, B13, ECp);						//A*A-B*B*B
	Rsub(S, T, TT, ECp);
	Rsub(P3->X, S, TT, ECp);					//X3 = A*A-B*B*B-2*X1*B*B

	Rsub(T, TT, P3->X, ECp);					//X1*B*B-X3
	Rmul(S, A, T, ECp);							//A*(X1*B*B-X3)
	Rmul(T, P1->Y, B13, ECp);					//Y1*B*B*B
	Rsub(P3->Y, S, T, ECp);						//Y3 = A*(X1*B*B-X3)-Y1*B*B*B

	Rmul(P3->Z, P1->Z, B, ECp);					//Z3 = Z1*B
}

//------------------------------------------------------
//Восстановление координаты Y
//------------------------------------------------------
void ECPy(ECP_affine *P, residue x)
{
	residue g, t;

	GF2MF(t, x, ECe2_p, ECp);
	Rmul(g, t, t, ECp);
	Radd(g, g, ECae, ECp);
	Rmul(g, g, t, ECp);
	Radd(g, g, ECbe, ECp);
	Rsqrt(t, g);
	MF2GF(P->y, t, ECp);
}

//------------------------------------------------------
//Копирование
//------------------------------------------------------
void Rcopy(residue dest, residue src)
{
	int i;

	for(i = 0; i < N; i++)
	{
		dest[i] = src[i];
	}
}

//------------------------------------------------------
//Сложение чисел (S = A + B) (mod P)
//------------------------------------------------------
void Radd(residue S, residue A, residue B, residue P)
{
	int i;
	long r;

	r = 0;
	for(i = 0; i < N; i++)
    {
		r = r + A[i] + B[i];
        S[i] = (short int)r;
		r >>= 16;
    }
	Mod(S, S, P);
}

//------------------------------------------------------
//Вычитание чисел (S = A - B) (mod P)
//------------------------------------------------------
void Rsub(residue S, residue A, residue B, residue P)
{
	int i;
	long r;

	r = 0;
	for(i = 0; i < N; i++)
    {
		r = r + A[i] - B[i];
        S[i] = (short int)r;
		r >>= 16;
    }
	if(r < 0)
    {
		r=0;
        for(i = 0; i < N; i++)
        {
			r = r + S[i] + P[i];
            S[i] = (short int)r;
			r >>= 16;
        }
    }
}

//------------------------------------------------------
//Умножение чисел (S = A * B) (mod P) - умножение Монтгомери
//------------------------------------------------------
void Rmul(residue S, residue A, residue B, residue P)
{
	int i, j;
	unsigned short int u, b, z;
	unsigned long int r0, r1;
	residue S0;

	if(P == ECp)
	{
		z = ECp0inv;
	}
	else
	{
		z = ECq0inv;
	}
	for(i = 0; i < N; i++)
	{
		S0[i] = 0;
	}
	for(i = 0; i < N; i++)
    {
		b   = B[i];
        r0  = A[0] * (unsigned long)b + S0[0];
        u   = ((short int)r0) * z;
        r1  = P[0] * (unsigned long)u;
        r0 += (unsigned short int)r1;
        r1>>= 16;
		r0>>= 16;
        for(j = 1; j < N; j++)
        {
			r1 += P[j] * (unsigned long)u + S0[j];
			r0 += A[j] * (unsigned long)b + ((unsigned short int)r1);
            S0[j - 1] = (unsigned short int)r0;
            r1 >>= 16;
			r0 >>= 16;
        }
        S0[N - 1] = (unsigned short int)(r1 + r0);
    }
	Rcopy(S, S0);
	Mod(S, S, P);
}

//------------------------------------------------------
//Возведение в степень (S = A ^ (P - 3)/4) (mod p)
//------------------------------------------------------
void Rpow_pdiv4(residue S, residue A, residue P)
{
	int m;

	Rcopy(S, A);
	for(m = n - 1; ((P[m >> 4] >> (m & 15)) & 1) == 0; m--);
	for(m--; m >= 2; m--)
    {
		Rmul(S, S, S, ECp);
        if(((P[m >> 4] >> (m & 15)) & 1) == 1)
		{
			Rmul(S, S, A, ECp);
		}
    }
}

//------------------------------------------------------
//Возведение в степень (S = A^B)(mod P)
//------------------------------------------------------
void Rstep(residue S, residue A, residue B, residue P)
{
	int m;
	unsigned short *E2;

	Rcopy(S, A);
	for(m = n - 1; ((B[m >> 4] >> (m & 15)) & 1) == 0; m--);
	if(m < 0)
	{
		if(P == ECp)
		{
			E2 = ECe2_p;
		}
		else
		{
			E2 = ECe2_q;
		}
		GF2MF(S, ECone, E2, P);
	}
	else
	{
		for(m--; m >= 0; m--)
		{
			Rmul(S, S, S, P);
			if(((B[m >> 4] >> (m & 15)) & 1) == 1)
			{
				Rmul(S, S, A, P);
			}
		}
	}
}

//------------------------------------------------------
//Нахождение обратного (S = A^-1)(mod P)
//------------------------------------------------------
void Rinv(residue S, residue A, residue P)
{
	unsigned short *PP;

	if(P == ECp)
	{
		PP = ECp_2;
	}
	else
	{
		PP = ECq_2;
	}
	Rstep(S, A, PP, P);
}

//------------------------------------------------------
//Деление на 2 в GF (S = A/2) 
//------------------------------------------------------
static void Div2(residue S, residue A)
{
	int i;

	for(i = 0; i < N - 1; i++)
	{
		S[i] = A[i] >> 1;
		S[i] |= (A[i + 1] & 0x01) << 15;
	}
	S[N - 1] = 0;
}

//------------------------------------------------------
//Сравнение двух длинных чисел (S != A (1), S == A (0))
//------------------------------------------------------
static int Rcmp(residue S, residue A)
{
	int i, res = 0;

	for(i = 0; i < N - 1; i++)
	{
		if(S[i] != A[i])
		{
			res = 1;
			break;
		}
	}
	return res;
}

//------------------------------------------------------
//Нахождение квадратичного невычета (B^(p - 1)/2 = -1 (mod p))
//------------------------------------------------------
static void Findb(residue S, residue START, residue P_12)
{
	int trying = 100;
	residue B, T, TT;

	Rcopy(TT, START);
	while(trying)
	{
		GF2MF(B, TT, ECe2_p, ECp);
		Rstep(T, B, P_12, ECp);
		MF2GF(B, T, ECp);
		Radd(T, B, ECone, ECp);
		if(!Rcmp(T, ECzr))
		{
			break;
		}
		Rsub(TT, TT, ECone, ECp);
	}
	Rcopy(S, TT);	
}

//------------------------------------------------------
//Извлечение квадратного корня 
//------------------------------------------------------
void Rsqrt(residue S, residue A)
{
	residue B, R1, R2, Ss, Sss, Z, T, P_1;

	if((ECp[0] & 0x03) == 0x03)
	{
		//p = 3 (mod4) -> x = a^((p + 1)/4) (mod p)
		Rpow_pdiv4(S, A, ECp);
		Rmul(S, S, A, ECp);
	}
	else
	{
		//Произвольный простой модуль
		Rsub(P_1, ECp, ECone, ECp);
		Div2(Ss, P_1);
		Findb(B, P_1, Ss);
		Rcopy(Sss, Ss);
		Rstep(R1, A, Sss, ECp);
		GF2MF(R2, ECone, ECe2_p, ECp);
		Rcopy(Z, ECzr);
		while(1)
		{
			Rmul(T, R1, R2, ECp);
			MF2GF(T, T, ECp);
			if(Rcmp(T, ECone))
			{
				if(!Rcmp(T, P_1))
				{
					Radd(Z, Z, Sss, ECp);
				}
			}
			Div2(Z, Z);
			if(Ss[0] & 0x01)
			{
				break;
			}
			Div2(Ss, Ss);
			Rstep(R1, A, Ss, ECp);
			Rstep(R2, B, Z, ECp);
		}
		Radd(Ss, Ss, ECone, ECp);
		Div2(Ss, Ss);
		Rstep(R1, A, Ss, ECp);
		Rstep(R2, B, Z, ECp);
		Rmul(S, R1, R2, ECp);
	}
}

//------------------------------------------------------------------------------------------
//Определение z = -P0^(-1)(mod b) (используется в умножении Монтгомери) 
//------------------------------------------------------------------------------------------
unsigned short Findz(unsigned short a)
{
	int i;
	unsigned short d;
	
	if((a & 1) == 0)
	{
		return 0;
	}
	for(i=0, d=a; i < 16 - 2; i++)
	{
		d *= d;
		d *= a;
	}
	return (0 - d);
}

//------------------------------------------------------------------------------------------
//Определение e = (2^16)^N(mod P) (проективная координата Z) 
//------------------------------------------------------------------------------------------
void Finde(residue RES, residue P)
{
	int i;

	for(i = 0; i < (N - 1); i++)
	{
		RES[i] = 0;
	}
	RES[i] = 0x0001;
	Mod(RES, RES, P);
	// * 2^16
	while(i)
	{
		RES[i] = RES[i - 1];
		i--;
	}
	RES[0] = 0x0000;
	Mod(RES, RES, P);
}

//------------------------------------------------------------------------------------------
//Нахождение B = A (mod P) 
//------------------------------------------------------------------------------------------
void Mod(residue B, residue A, residue P)
{
	Rsub(A, A, P, P);
	while(A[N - 1] || (A[N - 2] > P[N - 2]))
	{
		Rsub(A, A, P, P);
	}
	Rcopy(B, A);
}

//------------------------------------------------------
//Сравнение длинных чисел размерностью 2 * N
//Выход:
// - 0 - A > B
// - 1 - иначе 
//------------------------------------------------------
static unsigned int BigCmp(residue A, residue B) 
{
	int i;
	
	for(i = 2 * N - 1; i >= 0; i--)
	{
		if(A[i] > B[i])
		{
			return 0;
		}
		if(A[i] < B[i])
		{
			return 1;
		}
	}
	return 1;
}

//------------------------------------------------------
//Сдвиг числа размерностью на S слов вправо
//------------------------------------------------------
static void ModShift(residue A, residue B, int S)
{
	int i;
	
	for(i = 0; i < N - 1; i++)
	{
		A[N - 2 - i + S] = B[N - 2 - i];
	}
	for(i = 0; i < S; i++)
	{
		A[i] = 0;
	}
	for(i = N - 1 + S; i < 2 * N; i++)
	{
		A[i] = 0;
	}
}

//------------------------------------------------------
//Вычитание чисел размерность 2 * N по модулю P
//------------------------------------------------------
static void BigSub(residue A, residue B, residue P)
{
	long i, r;

	r = 0;
	while(r >= 0)
	{
		for(i = 0; i < 2 * N; i++)
		{
			r = r + A[i] - B[i];
			A[i] = (short int)r;
			r >>= 16;
		}
	}
	r = 0;
    for(i = 0; i < 2 * N; i++)
    {
		r = r + A[i] + P[i];
        A[i] = (short int)r;
		r >>= 16;
    }
}

//------------------------------------------------------
//Умножение чисел (S = A * B) (mod p) 
//------------------------------------------------------
void Mul(residue S, residue A, residue B, residue P)
{
	int i, j, k;
	unsigned short int d;
	unsigned long int T;
	unsigned short int TMP[2 * N];
	unsigned short int MOD[2 * N];
	unsigned short int MODs[2 * N];
	
	for(i = 0; i < N; i++)
	{
		TMP[i] = 0;
		MOD[i] = P[i];
	}
	for(i = N; i < 2 * N; i++)
	{
		MOD[i] = 0;
	}
	for(i = 0; i < N; i++)
	{
		d = 0;
		for(j = 0; j < N; j++)
		{
			T = (unsigned long int)A[i] * B[j] + TMP[i + j] + d;
			TMP[i + j] = (unsigned short)T;
			d = (unsigned short)(T >> 16);
		}
		TMP[i + j] = d;
	}
	//Вычисление модуля
	//Определение номера старшего слова числа
	for(j = 2 * N; (TMP[j - 1] == 0) && (j != 0); j--);
	if(j < (N - 1))
	{
		Rcopy(S, TMP);
		return;
	}
	//Определение сдвига модуля
	k = j - N + 1;
	while(k)
	{
		//Сдвиг модуля
		ModShift(MODs, MOD, k);
		//Сравнение и вычитание
		if(!BigCmp(TMP, MODs))
		{
			BigSub(TMP, MODs, MODs);
		}
		k--;
	}
	BigSub(TMP, MOD, MOD);
	Rcopy(S, TMP);
}



