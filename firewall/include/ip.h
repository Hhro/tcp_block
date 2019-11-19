#pragma once

#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/types.h>
#include "udp.h"
#include "tcp.h"
#include "utils.h"

#define IP_HLEN 20

void mangle_ip(char *saddr, char *daddr, uint8_t proto, uint16_t payload_len, struct iphdr *ip);
void set_ip_checksum(struct iphdr *ip, size_t size);
