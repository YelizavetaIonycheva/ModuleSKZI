#ifndef _MMT_H
#define _MMT_H

#include "IKEv2.h"

typedef struct ikev2_tunnel{
    unsigned int ip_wan;
    unsigned int ip_net;
    unsigned int mask_net;
    unsigned short net_num;
    unsigned short port;
    unsigned char index;
    unsigned char reserv;
    unsigned short index_tunel;
}ikev2_TUNNEL;

typedef struct mmt_wait_paket {
    unsigned short net_num;
    unsigned char * data;
    unsigned int len_data;
}mmt_WAIT_PACKET;

typedef struct mmt_wait_paket_chain {
    mmt_WAIT_PACKET * value;
    struct mmt_WAIT_PACKET_CHAIN * next;
}mmt_WAIT_PACKET_CHAIN;

typedef struct ikev2_sa_additional_chain {
    IKEv2_STRUCT_SA * value;
    time_t last_time_response;
    time_t last_time_keepalive;
    char count_keepalive;
    struct IKEV2_SA_ADDITINAL_CHAIN * next;
}IKEV2_SA_ADDITINAL_CHAIN;

typedef struct mmt_tunnel_chain {
    ikev2_TUNNEL * tunnel;
    struct mmt_TUNNEL_CHAIN * next;
}mmt_TUNNEL_CHAIN;



#define SIZE_TUNNEL_STRUCT sizeof(ikev2_TUNNEL)
#define IKEv2_NEW 1
#define IKEv2_OLD 2
#define NOT_SEND 1

#define TIME_BETWEEN_RESPONSE_I 5
#define TIME_BETWEEN_RESPONSE_R 30
#define TIME_BETWEEN_KEEPALIVE 2
#define MAX_KEEPALIVE 2

unsigned int mmt_save_tunnel(unsigned char *data, int len_data);
unsigned int tunnels_have_nn(unsigned short net_num);
unsigned int proc_pack_for_another_network(unsigned char *data_in, int len_data_in,
                                           unsigned char **data_out, int *len_data_out);
unsigned int check_ikev2_sa_a(unsigned char **data_out, int *len_data_out);
unsigned int search_netnum_by_ipnetwork(unsigned int dest_ip, unsigned short * net_num);
void ikev2_sa_a_init(IKEv2_STRUCT_SA *ikev2_sa_a, unsigned char role,
                              unsigned short net_num, unsigned short server_net_number);
unsigned int check_ike_sa_a_auth(IKEv2_STRUCT_SA *ikev2_sa_a, unsigned char *data, int lenData);
unsigned int get_ikev2_sa_a_by_nn(unsigned short server_net_number, IKEv2_STRUCT_SA **ikev2_sa_a);
unsigned int get_ikev2_sa_a_by_spi(IKEv2_STRUCT_SA **ikev2_sa_a, unsigned char * spi);
unsigned int get_ikev2_sa_a_by_espspi(IKEv2_STRUCT_SA **ikev2_sa_a, unsigned int spi);
void mmt_get_keepalive(IKEv2_STRUCT_SA *ikev2_sa_a, unsigned char **dataOut, int *lenDataOut);
unsigned int mmt_check_ike_sa_a_auth(unsigned char *data_in, int len_data_in,
                                     unsigned char **data_out, int *len_data_out);
unsigned int mmt_check_ike_sa_a_init(unsigned char *data_in, int len_data_in,
                                     unsigned char **data_out, int *len_data_out);

void delete_all_ikev2_sa_a();
void delete_all_wait_packets();
void delete_all_tunnels();

#endif