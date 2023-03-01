#ifndef _UPDSCH_H_
#define _UPDSCH_H_

#include <android/log.h>
//#define _TESTING_

typedef struct
{
	unsigned char k_dsch[32];					//ключ ДСЧ без маски
	unsigned char k_ij[32];						//ключ парной связи
	unsigned char tz[64];						//узлы замены без маски
	unsigned char sp[8];						//синхропосылка
	unsigned char sn1[10];						//серийный номер изделия
	unsigned char sn2[10];						//серийный номер аппаратуры изготовления ключей
	unsigned char r[64];						//источник энтропии
	unsigned char k[32];						//источник энтропии
} updsch_struct;	 

void updsch_init(updsch_struct *updsch, unsigned char *SecureIdentifyInf);
void updsch_gen_sp(int takt, unsigned char *m, unsigned char *sp, unsigned char *SecureIdentifyInf);
void updsch_gen_sp_pp(int takt, unsigned char *m_pp, unsigned char *sp_pp, unsigned char *SecureIdentifyInf_pp); 
unsigned char updsch_init_pp(unsigned char *key, unsigned char *user_id, unsigned char *SecureIdentifyInf_pp);

#define TAG "UPDSCH_LOG"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)

#endif

