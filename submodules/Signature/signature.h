#ifndef _SIGNATURE_H_
#define _SIGNATURE_H_

unsigned char ecp_form(unsigned char * key, unsigned char * data, unsigned int len_data, unsigned char ** result, unsigned int * len_result);
unsigned char ecp_control(unsigned char * key, unsigned char * data, unsigned int len_data, unsigned char * ecp, unsigned int len_ecp);
unsigned char * get_key_form(int num_key);
unsigned char * get_key_control(int num_key);
#endif