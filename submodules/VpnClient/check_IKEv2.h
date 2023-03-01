#ifndef H_CKECKIKEV2
#define H_CKECKIKEV2

#include "IKEv2.h"

unsigned int check_block_hdr(ikev2_block_HDR * block_HDR, IKEv2_STRUCT_SA * ikev2_sa);

// Функция проверки ответа IKE_SA_INIT
// Если проверка пройдена сохраняет полученные параметры
unsigned int ikev2_check_ike_sa_init(unsigned char *data, int lenData, IKEv2_STRUCT_SA * ikev2_sa);

// Функция проверки предложенй выбранных сервером
unsigned int checkSavedProposals(ikev2_block_SA * block_SA);

/* Функция проверки ответа IKE_SA_AUTH
 * Входные параметры:
 *		data - указатель на блок SK
 *		lenData - размер блока SK
 * Выходные параметры:
 *		результат проверки (0 - пройдена)
 */
unsigned int check_ike_sa_auth(unsigned char * data, int lenData, IKEv2_STRUCT_SA * ikev2_sa);

#endif