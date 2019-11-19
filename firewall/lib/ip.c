#include "ip.h"

void mangle_ip(char *saddr, char *daddr, uint8_t proto, uint16_t payload_len, struct iphdr *ip){
    ip->version = 4;
    ip->ihl = 5;
    ip->frag_off = htons(0x4000);
    ip->ttl = 128;
    ip->protocol = proto;

    if(proto == IPPROTO_UDP){
        ip->tot_len = htons(ip->ihl*4 + UDP_HLEN + payload_len);
    }
    else if(proto == IPPROTO_TCP){
        ip->tot_len = htons(ip->ihl*4 + TCP_HLEN + payload_len);
    }

    memcpy(&ip->saddr, saddr, 4);
    memcpy(&ip->daddr, daddr, 4);
}

void set_ip_checksum(struct iphdr *ip, size_t size){
    ip->check = calc_checksum(ip, size);
}