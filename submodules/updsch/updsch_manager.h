#ifndef _UPDSCH_MANAGER_H_
#define _UPDSCH_MANAGER_H_

unsigned char init_updsch(unsigned char * key_dsch, unsigned char * key, unsigned char * table, unsigned char *SecureIdentifyInf, unsigned char * init_data);
unsigned char * get_random(unsigned char *SecureIdentifyInf);

unsigned char init_updsch_pp(unsigned char *key, unsigned char *user_id, unsigned char *SecureIdentifyInf_pp);
unsigned char * get_random_pp(unsigned char *SecureIdentifyInf_pp);

#endif