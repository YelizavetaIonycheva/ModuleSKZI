#include <stdio.h>
#include "ecp_341012.h"

/*****************************************************************************************/
//Исходные данные
/*****************************************************************************************/
//p (модуль эллиптической кривой)
residue ECp;

residue ECp_2;

//a (коэффициент эллиптической кривой в поле Монтгомери)
residue ECae;

//b (коэффициент эллиптической кривой в поле Монтгомери)
residue ECbe;

//q (порядок циклической подгруппы группы точек эллиптической кривой)
residue ECq;

residue ECq_2;

//P0x (коэффициент точки эллиптическрй кривой)
residue ECUx;

//P0y (коэффициент точки эллиптическрй кривой)
residue ECUy;

residue ECe_p;

residue ECe_q;

residue ECe2_p;

residue ECe2_q;

residue ECone  = {0x0001, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000};

residue Const2 = {0x0002, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,};

residue ECzr =   {0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000};

unsigned short int ECp0inv = 0;
unsigned short int ECq0inv = 0;
/*****************************************************************************************/

//-----------------------------------------------------------------
//Проверка длинного числа на 0
//На входе:
//		- длинное число
//На выходе:
//		- результат (0-не равно,1-равно)
//-----------------------------------------------------------------
static unsigned short IsNull(unsigned char *digit)
{
	int i;

	for(i = 0; i < SIZE; i++)
	{
		if(digit[i])
		{
			return 0;
		}
	}
	return 1;
}

//-----------------------------------------------------------------
//Проверка неравенства (0 < digit < q)
//На входе:
//		- длинное число
//На выходе:
//		- результат (0-не удовлетворяет,1-удовлетворяет)
//-----------------------------------------------------------------
static unsigned short IsCmp(unsigned char *digit)
{
	int i;
	
	if(IsNull(digit))
	{
		return 0;
	}
	i = SIZE;
	while(i)
	{
		if(*((unsigned char *)ECq + i - 1) > digit[i - 1])
		{
			return 1;
		}
		else if(*((unsigned char *)ECq + i - 1) < digit[i - 1])
		{
			return 0;
		}
		i--;
	}
	return 0;
}

//-----------------------------------------------------------------
//Формирование ЭЦП
//На входе:
//		- структура с данными
//На входе:
//		- результат работы (0-ошибка-некоррекное К,1-норма)
//-----------------------------------------------------------------
static unsigned short EcpForm(EcpStruct * Data)
{
	int i;
	residue h, e, r, d, k, s;
	ECP_affine U;

	//Переписываем ХЭШ, k и d
	for(i = 0; i < (N - 1) * 2; i++)
	{
		*((unsigned char *)h + i) = Data->Hesh[i];
		*((unsigned char *)k + i) = Data->K[i];
		*((unsigned char *)d + i) = Data->Skey[i];
	}
	h[N - 1] = 0;
	k[N - 1] = 0;
	d[N - 1] = 0;
	//ШАГ 2 (e = a(modq))
	Mod(e, h, ECq);
	//Проверка на 0
	if(IsNull((unsigned char *)e))
	{
		//e = 1
		e[0] = 0x0001; 
	}
	//ШАГ 3 (0 < k < q)
	Mod(k, k, ECq);
	if(!IsCmp((unsigned char *)k))
	{
		return 0;
	}
	//ШАГ 4 (C = kP)
	Rcopy(U.x, ECUx);
	Rcopy(U.y, ECUy);
	ECPpow(&U, &U, k);
	//r = Xc(modq)
	Mod(r, U.x, ECq);
	//Проверка на 0
	if(IsNull((unsigned char *)r))
	{
		return 0;
	}
	//ШАГ 5 (s = (rd + ke)(modq))
	GF2MF(s, r, ECe2_q, ECq);
	GF2MF(d, d, ECe2_q, ECq);
	GF2MF(k, k, ECe2_q, ECq);
	GF2MF(e, e, ECe2_q, ECq);
	Rmul(h, s, d, ECq);
	Rmul(e, k, e, ECq);
	Radd(s, h, e, ECq);
	MF2GF(s, s, ECq);
	Mod(s, s, ECq);
	//Переписываем результат r || s
	for(i = 0; i < SIZE; i++)
	{
		Data->Ecp[i]        = *((unsigned char *)r + i);
		Data->Ecp[i + SIZE] = *((unsigned char *)s + i);
	}
	return 1;
}

//-----------------------------------------------------------------
//Проверка ЭЦП (спомогательная функция)
//На входе:
//		- данные 
//На входе:
//		- результат работы (0-ошибка-ЭЦП не верна,1-норма)
//-----------------------------------------------------------------
static unsigned short EcpCheck(residue e, residue r, residue s, residue x, residue y)
{
	ECP_affine U, V;
	ECP_projective C;
	residue v, z1, z2;
	residue ee, ss, rr;
	int i;
	
	GF2MF(ee, e, ECe2_q, ECq);
	GF2MF(ss, s, ECe2_q, ECq);
	GF2MF(rr, r, ECe2_q, ECq);
	GF2MF(ECzr, ECzr, ECe2_q, ECq);
	//ШАГ 4 (v = e^-1(modq))
	Rinv(v, ee, ECq);
	//ШАГ 5 (z1 = sv(modq), z2 = -rv(modq))
	Rmul(z1, ss, v, ECq);
	Rmul(z2, rr, v, ECq);
	Rsub(z2, ECzr, z2, ECq);
	MF2GF(z1, z1, ECq);
	MF2GF(z2, z2, ECq);
	//ШАГ 6 (С = z1P + z2Q)
	Rcopy(U.x, ECUx);
	Rcopy(U.y, ECUy);
	ECPpow(&U, &U, z1);
	Rcopy(V.x, x);
	Rcopy(V.y, y);
	ECPpow(&V, &V, z2);
	affine2projective(&C, &U);
	ECPmul(&C, &C, &V);
	projective2affine(&U, &C);
	//R = Xc(modq)
	Mod(v, U.x, ECq);
	//ШАГ 7 сравниваем подписи (v и r)
	for(i = 0; i < (N - 1); i++)
	{
		if(v[i] != r[i])
		{
			return 0;
		}
	}
	return 1;
}

//-----------------------------------------------------------------
//Проверка ЭЦП
//На входе:
//		- структура с данными
//На входе:
//		- результат работы (0-ошибка-ЭЦП не верна,1-норма)
//-----------------------------------------------------------------
static unsigned short EcpControl(EcpStruct * Data)
{
	unsigned int i;
	residue h, e, r, s, x, y;

	//ШАГ 1 (r и s) ШАГ 2 (h)
	if((IsNull(Data->Ecp)) || (IsNull(Data->Ecp + SIZE)))
	{
		return 0;
	}
	for(i = 0; i < (N - 1) * 2; i++)
	{
		*((unsigned char *)r + i) = Data->Ecp[i];
		*((unsigned char *)s + i) = Data->Ecp[i + SIZE];
		*((unsigned char *)h + i) = Data->Hesh[i];
		*((unsigned char *)x + i) = Data->Okey[i];
        *((unsigned char *)y + i) = Data->Okey[i + SIZE];
	}
	r[N - 1] = 0;
	s[N - 1] = 0;
	h[N - 1] = 0;
	x[N - 1] = 0;
    y[N - 1] = 0;
	//ШАГ 3 (e = a(modq))
	Mod(e, h, ECq);
	//Проверка на 0
	if(IsNull((unsigned char *)e))
	{
		//e = 1
		e[0] = 0x0001;
	}
	if(!EcpCheck(e, r, s, x, y))
	{
		return 0;
	}
	return 1;
}

/*****************************************************************/
//Инициализация параметров ЭЦП
//На входе:
//		- указатель на структуру с данными
//На выходе:
//		- результат работы (0-ошибка,1-норма)
/*****************************************************************/
unsigned short InitEcp341012(InitEcpStruct * Data)
{
	unsigned int i;
	residue Tmp, Tmp1, A, B;
	
	//Запись параметров
	for(i = 0; i < (N - 1) * 2; i++)
	{
		*((unsigned char *)ECp + i)  = Data->P[i];			//модуль эллиптической кривой
		*((unsigned char *)ECq + i)  = Data->Q[i];			//порядок циклической подгруппы группы точек эллиптической кривой
		*((unsigned char *)A + i)	 = Data->A[i];			//коэффициент А эллиптической кривой
		*((unsigned char *)B + i)	 = Data->B[i];			//коэффициент B эллиптической кривой
		*((unsigned char *)ECUx + i) = Data->Px[i];			//координата X точки эллиптической кривой
		*((unsigned char *)ECUy + i) = Data->Py[i];			//координата Y точки эллиптической кривой
	}
	ECp[N - 1]  = 0;
	ECq[N - 1]  = 0;
	A[N - 1]	= 0;
	B[N - 1]	= 0;
	ECUx[N - 1] = 0;
	ECUy[N - 1] = 0;
	//Определение z = -P0^(-1)(mod b) (используется в умножении Монтгомери) 
	ECp0inv = Findz(ECp[0]);
	ECq0inv = Findz(ECq[0]);
	if((!ECp0inv) || (!ECq0inv))
	{
		ECp0inv = 0;
		ECq0inv = 0;
		return 0;
	}
	//Определение e = (2^16)^N(mod P) (проективная координата Z) 
	Finde(ECe_p, ECp);
	Finde(ECe_q, ECq);
	//Проверка
	Rmul(Tmp,  ECe_p, ECe_p, ECp);
	Rmul(Tmp1, ECe_q, ECe_q, ECq);
	for(i = 0; i < (N - 1); i++)
	{
		if((Tmp[i] != ECe_p[i]) || (Tmp1[i] != ECe_q[i]))
		{
			ECp0inv = 0;
			ECq0inv = 0;
			return 0;
		}
	}
	//Определение e2 = e^2(mod P)
	Mul(ECe2_p, ECe_p, ECe_p, ECp);
	Mul(ECe2_q, ECe_q, ECe_q, ECq);
	GF2MF(ECae, A, ECe2_p, ECp);
	GF2MF(ECbe, B, ECe2_p, ECp);	
	//Нахождение P-2 и Q-2 (для вычисления обратного элемента)
	Rsub(ECp_2, ECp, Const2, ECp);
	Rsub(ECq_2, ECq, Const2, ECq);
	return 1;
}


/*****************************************************************/
//Программная реализация алгоритма ЭЦП по ГОСТ 34.10-2012
//На входе:
//		- указатель на структуру с данными
//На выходе:
//		- результат работы (0-ошибка,1-норма)
/*****************************************************************/
unsigned short Ecp341012(EcpStruct * Data)
{
	unsigned short res = 0;

	if(ECp0inv && ECq0inv)
	{
		switch(Data->Pr)
		{
			//Формирование ЭЦП
			case ECP_FORM:
				if((Data->Hesh == NULL) || (Data->Skey == NULL) || (Data->Ecp == NULL) || (Data->K == NULL))
				{
					break;
				}
				res = EcpForm(Data);
				break;
			//Проверка ЭЦП
			case ECP_CONTROL:
				if((Data->Hesh == NULL) || (Data->Okey == NULL) || (Data->Ecp == NULL))
				{
					break;
				}
				res = EcpControl(Data);
				break;
		}
	}
	return res;
}

