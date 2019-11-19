#include "udp.h"

void mangle_udp(uint16_t sport, uint16_t dport, uint16_t len, struct udphdr *udp){
    udp->source = sport;
    udp->dest = dport;
    udp->len = len;
}

void set_udp_checksum(struct iphdr *ip, struct udphdr *udp, size_t udp_size){
    struct pseudo_ip pip;
    int completed_len = sizeof(struct pseudo_ip) + udp_size;
    uint8_t *completed = (uint8_t*)calloc(sizeof(uint8_t) * completed_len, 1);

    memcpy(&pip.daddr, (char*)&ip->daddr, 4);
    memcpy(&pip.saddr, (char*)&ip->saddr, 4);
    pip.reserved = 0;
    pip.protocol = IPPROTO_UDP;
    pip.size = htons(udp_size);

    memcpy(completed, &pip, sizeof(pip));
    memcpy(completed + sizeof(pip), udp, udp_size);

    udp->check = calc_checksum(completed, completed_len);

    free(completed);
}