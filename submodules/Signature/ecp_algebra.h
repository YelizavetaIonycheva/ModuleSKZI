#ifndef _ALGEBRA_H_
#define _ALGEBRA_H_

/**************************************************************/
//Переменные и массивы
/**************************************************************/

/**************************************************************/
//Константы
/**************************************************************/
#define n			112
#define N			8
#define SIZE		(2 * (N - 1))		//размерность в байтах

/**************************************************************/
//Типы данных
/**************************************************************/
typedef unsigned short int residue[N];
typedef struct {residue x,y;} ECP_affine;
typedef struct {residue X,Y,Z;} ECP_projective;

/**************************************************************/
//Внешние ссылки
/**************************************************************/
extern residue ECp;
extern residue ECp_2;
extern residue ECae;
extern residue ECbe;
extern residue ECq;
extern residue ECq_2;
extern residue ECUx;
extern residue ECUy;
extern residue ECe_p;
extern residue ECe_q;
extern residue ECe2_p;
extern residue ECe2_q;
extern residue ECone;
extern residue ECzr;
extern unsigned short int ECp0inv;
extern unsigned short int ECq0inv;

/**************************************************************/
//Прототипы функций
/**************************************************************/
void ECPpow(ECP_affine *Ps, ECP_affine *P, residue s);
void affine2projective(ECP_projective *Pp, ECP_affine *Pa);
void projective2affine(ECP_affine *Pa, ECP_projective *Pp);
void ECPmul(ECP_projective *P3, ECP_projective *P1, ECP_affine *P2);
void ECPy(ECP_affine *P, residue x);

void Rcopy(residue dest, residue src);
void Radd(residue S, residue A, residue B, residue P);
void Rsub(residue S, residue A, residue B, residue P);
void Rmul(residue S, residue A, residue B, residue P);
void Rpow_pdiv4(residue S, residue A, residue P);
void Rstep(residue S, residue A, residue B, residue P);
void Rinv(residue S, residue A, residue P);
void Rsqrt(residue S, residue A);
unsigned short Findz(unsigned short a);
void Finde(residue RES, residue P);
void Mod(residue B, residue A, residue P);
void Mul(residue S, residue A, residue B, residue P);

/**************************************************************/
//Макросы
/**************************************************************/
//Переход из поля Галуа в поле Монтгомери
#define GF2MF(S, A, E, P)	Rmul(S, A, E, P)
//Переход из поля Монтгомери в поле Галуа 	
#define MF2GF(S, A, P)		Rmul(S, A, ECone, P)


#endif





