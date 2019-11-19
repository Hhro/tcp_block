#pragma once

#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#include <linux/types.h>
#include <linux/if_ether.h>

void mangle_ether(char *dst, char *src, struct ethhdr *eth);
