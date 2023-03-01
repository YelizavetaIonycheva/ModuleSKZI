#ifndef _F_H 
#define _F_H 

#include "IKEv2.h"

#define SEANS_RND_S             0
#define SEANS_RND_D             1
#define SEANS_ALPHA             0x87
#define SEANS_N(n)              (1 << n)
#define SEANS_MUL_ALPHA(x)      ((x & 0x80) ? (x << 1) ^ SEANS_ALPHA : x << 1)

#if defined(CRYPT_GOST28147)
    extern unsigned char T_EXP[256];
    extern unsigned char T_LOG[256];
#endif

void get_packet_key(unsigned int  *key,        //адрес KEI (KER)
                    unsigned char *SP,         //адрес SP(8 byte)
                    unsigned int  *pak_key    //адрес пакетного key
);

#endif