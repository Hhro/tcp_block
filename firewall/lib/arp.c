#include <pcap.h>
#include <linux/if_ether.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "arp.h"
#include "pkt.h"

void get_target_hw(pcap_t *handle, struct net_info *ninfo, char *tip, char *thw){
    char dev_mac_str[18];
    char filter[100] = "ether proto 0x0806 and ether dst host ";

    BZERO(dev_mac_str, 18);

    mac_ntop(ninfo->dev_mac, dev_mac_str);
    strcat(filter, dev_mac_str);

    set_pcap_filter(handle, filter, (bpf_u_int32)(*ninfo->dev_ip));
    send_arp_req(handle, ninfo, tip);
    recv_arp_reply(handle, ninfo, tip, thw);
}

void send_arp_req(pcap_t *handle, struct net_info *ninfo, char *tip){
    struct ethhdr eth;
    struct arphdr arp;

    memset(eth.h_dest, 0xff, ETH_ALEN);
    memcpy(eth.h_source, ninfo->dev_mac, ETH_ALEN);
    eth.h_proto = htons(ETH_P_ARP);

    arp.ar_hrd = htons(ARPHRD_ETHER);
    arp.ar_pro = htons(ETH_P_IP);
    arp.ar_hln = ETH_ALEN;
    arp.ar_pln = 4;
    arp.ar_op = htons(ARPOP_REQUEST);

    memcpy(arp.ar_sha, ninfo->dev_mac, ETH_ALEN);
    memcpy(arp.ar_sip, ninfo->dev_ip, 4);
    memset(arp.ar_tha, 0, ETH_ALEN);
    memcpy(arp.ar_tip, tip, 4);

    char *pkt = (char*)calloc(sizeof(char) * ETH_HLEN + ARP_LEN, 1);
    memcpy(pkt, &eth, ETH_HLEN);
    memcpy(pkt+ETH_HLEN, &arp, ARP_LEN);

    send_pkt(handle, pkt, ETH_HLEN + ARP_LEN);

    free(pkt);
}

void recv_arp_reply(pcap_t *handle, struct net_info *ninfo, char *tip, char *tha){
    struct pcap_pkthdr *header;
    const unsigned char *packet;
    struct arphdr *arp;

    while(1){
        int res = pcap_next_ex(handle, &header, &packet);

        arp = ARP(packet);
        if(!memcmp(arp->ar_sip, tip, 4)){
            memcpy(tha, arp->ar_sha, ETH_ALEN);
            break;
        }
    }
}
