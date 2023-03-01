
#include <string.h>

#include "F.h"
#if defined(CRYPT_GOST28147)
    #include "Gost28147.h"
    unsigned char T_EXP[256];
    unsigned char T_LOG[256];
#elif defined(CRYPT_MAGMA)
    #include "cypher.h"
#endif


static unsigned char xmul(unsigned char x, unsigned char y)
{
    unsigned short t = x * y + x + y;
    return ((t & 0xFF) < (t >> 8)) ? t - (t >> 8) + 1 : t - (t >> 8);
}

static void ff(unsigned int *key, unsigned char *SP, unsigned int *pak_key)
{
#if defined(CRYPT_GOST28147)
    unsigned short i,N;
    unsigned char s,s1,d,u,u1;
    unsigned int temp_shifr1[8],temp_shifr2[8];
    unsigned char *Z,*Z1,*Z2;                       //массив для выработки пакетного key
    Z=(unsigned char*) key;
    Z1=(unsigned char*) temp_shifr1;
    Z2=(unsigned char*) temp_shifr2;
    s=0; d=1;
    for(N=0; N<5; N++)
    {
        for(i=0; i<32; i++)
        {
            s1=s^(1<<N);
            if(s<s1)
            {
                u=Z[s]^Z[s1];
                if(Z[s]==0)
                    u1=Z[s1];
                else
                    u1=T_EXP[T_LOG[Z[s]]+1]^Z[s1];
                if((u==0)||(SP[s&7]==0))
                    Z1[s]=0;
                else
                    Z1[s]=T_EXP[(T_LOG[u]+T_LOG[SP[s&7]])%255];
                if((u1==0)||(SP[s1&7]==0))
                    Z1[s1]=0;
                else
                    Z1[s1]=T_EXP[(T_LOG[u1]+T_LOG[SP[s1&7]])%255];
            }
            s=(s+d)&31;
        }
        Z2=Z1;
        Z=Z1;
        Z1=Z2;
    }

    memcpy(pak_key, Z, SIZE_KEY);
#elif defined(CRYPT_MAGMA)
    int N, m, s, d, s_;
    unsigned char u, u_;
    unsigned char z[32];

    memcpy(z, key, 32);
    for (N=0; N<5; N++)
    {
        s = SEANS_RND_S;
        d = SEANS_RND_D;
        for (m=0; m<32; m++)
        {
            s_ = s ^ SEANS_N(N);
            if (s < s_)
            {
                u = z[s] ^ z[s_];
                u_= SEANS_MUL_ALPHA(z[s]) ^ z[s_];
                z[s] = xmul(u ,SP[s & 7]);
                z[s_]= xmul(u_,SP[s_& 7]);
            }
            s = (s + d) & 31;
        }
    }
    memcpy(pak_key, z, sizeof(z));
#endif
}

void get_packet_key(unsigned int  *key,        //адрес KEI (KER)
                    unsigned char *SP,         //адрес SP(8 byte)
                    unsigned int  *pak_key    //адрес пакетного key
) {
    unsigned char temp_key[32], pak_key_temp[32];
    ff(key, SP, pak_key);
    memcpy(temp_key, (unsigned char *)pak_key, 32);

#if defined(CRYPT_GOST28147)
    GostStruct Cript;
    Cript.REGIM	= GAMMIROVANIE_OS_REG;
    Cript.CRYPT	= ENCRYPT;
    Cript.Key	= (unsigned int*)temp_key;
    Cript.Sp	= (unsigned int *)(SP);
    Cript.Din	= (unsigned char *)(pak_key);
    Cript.Dout	= (unsigned char *)(pak_key);
    Cript.LenBytes = SIZE_KEY;
    Cript.TR_STATE = TR_NO;
	Cript.Tz	= (unsigned char *)ikev2_sa->blockNote.Table;
    Gost28147(&Cript);
#elif defined(CRYPT_MAGMA)
    unsigned char ctx[kCfb89ContextLen];
    if(!cypher_magma_cfb_init(temp_key, ctx, kBlockLen89, SP, 8))
        return;
    if(!cypher_encr_cfb(ctx, (unsigned char *)pak_key, pak_key_temp, SIZE_KEY))
        return;
    free_cfb(ctx);
    memcpy((unsigned char *)pak_key, pak_key_temp, SIZE_KEY);
#endif
}
