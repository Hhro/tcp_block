#pragma once

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <pcap.h>

#define BZERO(buf, len) memset(buf, 0, len)

#define ETH(pkt)    ((struct ethhdr*)(pkt))
#define IP(pkt)    ((struct iphdr*)(pkt + ETH_HLEN))

struct net_info{
    pcap_t *handle;
    char *dev;
    char dev_mac[ETH_ALEN];
    char dev_ip[4];
    char ins_mac[ETH_ALEN];
    char ins_ip[4];
    char app_mac[ETH_ALEN];
    char app_ip[4];
    char gw_mac[ETH_ALEN];
    char gw_ip[4];
};

#include "arp.h"

void mac_ntop(char *mac, char *mac_s);
void get_dev_info(struct net_info *ninfo);

#ifdef DEBUG
    void print_mac(char *mac, char *prefix);
    void print_ip(char *ip, char *prefix);
    void print_network_info(struct net_info *ninfo);
#endif

uint16_t calc_checksum(void* vdata,size_t length);
void grab_network_info(struct net_info *ninfo);