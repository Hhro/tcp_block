#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <linux/tcp.h>
#include <linux/types.h>

#include "ether.h"
#include "ip.h"
#include "utils.h"

#define TCP_HLEN    20

struct pseudo_ip{
    uint32_t saddr;
    uint32_t daddr;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t size;
};

void mangle_tcp_rst_ack(uint16_t sport, uint16_t dport, int seq, int ack, struct tcphdr *tcp);
void mangle_closer(char *shw, char *dhw, char *saddr, char *daddr, uint16_t sport, uint16_t dport, int seq, int ack, char *closer);
void set_tcp_checksum(struct iphdr *ip, struct tcphdr *tcp, size_t tcp_size);
