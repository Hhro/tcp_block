#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <linux/types.h>
#include <linux/udp.h>

#include "tcp.h"

#define UDP_HLEN    8

void mangle_udp(uint16_t sport, uint16_t dport, uint16_t len, struct udphdr *udp);
void set_udp_checksum(struct iphdr *ip, struct udphdr *udp, size_t udp_size);