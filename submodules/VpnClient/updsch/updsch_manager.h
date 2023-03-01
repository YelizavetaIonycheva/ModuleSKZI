#ifndef _UPDSCH_MANAGER_H_
#define _UPDSCH_MANAGER_H_

unsigned char init_updsch(unsigned char * key_dsch, unsigned char * key, unsigned char * table, unsigned char *SecureIdentifyInf);
unsigned char * get_random(unsigned char *SecureIdentifyInf);



#endif