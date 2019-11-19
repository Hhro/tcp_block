#include "tcp.h"

void mangle_tcp_rst_ack(uint16_t sport, uint16_t dport, int seq, int ack, struct tcphdr *tcp){
        tcp->source = sport;
        tcp->dest = dport;
        tcp->seq = seq;
        tcp->ack_seq = ack;
        tcp->doff = TCP_HLEN / 4;
        tcp->ack = 1;
        tcp->rst = 1;
}

void mangle_closer(char *shw, char *dhw, char *saddr, char *daddr, uint16_t sport, uint16_t dport, int seq, int ack, char *closer){
    struct ethhdr closer_eth;
    struct iphdr closer_ip;
    struct tcphdr closer_tcp;

    BZERO(&closer_eth, ETH_HLEN);
    BZERO(&closer_ip, 0x14);
    BZERO(&closer_tcp, 0x14);

    mangle_ether(dhw, shw, &closer_eth);
    
    mangle_ip(saddr, daddr, IPPROTO_TCP, 0, &closer_ip);
    closer_ip.tot_len = htons(40);
    set_ip_checksum(&closer_ip, IP_HLEN);

    mangle_tcp_rst_ack(sport, dport, seq, ack, &closer_tcp);
    set_tcp_checksum(&closer_ip, &closer_tcp, TCP_HLEN);

    memcpy(closer, &closer_eth, ETH_HLEN);
    memcpy(closer + ETH_HLEN, &closer_ip, IP_HLEN);
    memcpy(closer + ETH_HLEN + IP_HLEN, &closer_tcp, TCP_HLEN);
}

void set_tcp_checksum(struct iphdr *ip, struct tcphdr *tcp, size_t tcp_size){
    struct pseudo_ip pip;
    int completed_len = sizeof(struct pseudo_ip) + tcp_size;
    uint8_t *completed = (uint8_t*)calloc(sizeof(uint8_t) * completed_len, 1);

    memcpy(&pip.daddr, (char*)&ip->daddr, 4);
    memcpy(&pip.saddr, (char*)&ip->saddr, 4);
    pip.reserved = 0;
    pip.protocol = IPPROTO_TCP;
    pip.size = htons(tcp_size);

    memcpy(completed, &pip, sizeof(pip));
    memcpy(completed + sizeof(pip), tcp, tcp_size);

    tcp->check = calc_checksum(completed, completed_len);

    free(completed);
}