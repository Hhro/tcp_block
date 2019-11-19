#include "ether.h"

void mangle_ether(char *dst, char *src, struct ethhdr *eth){
    memcpy(eth->h_dest, dst, ETH_ALEN);
    memcpy(eth->h_source, src, ETH_ALEN);
    eth->h_proto = htons(ETH_P_IP);
}