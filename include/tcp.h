#pragma once

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <pcap.h>
#include <linux/types.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
#include "utils.h"
#include "ether.h"
#include "ip.h"
#include "xpkt.h"

#define TCP_HLEN    20
#define TCP(pkt)    (reinterpret_cast<struct tcphdr *>(pkt + ETH_HLEN + IP_HLEN))

struct pseudo_ip{
    uint32_t saddr;
    uint32_t daddr;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t size;
};

class Tcp : public Xpkt{
    private:
        pktword_n tcp_src;
        pktword_n tcp_dst;
        pktdword_n tcp_seq;
        pktdword_n tcp_ack_seq;

        pktword_n   tcp_doff:4,
                    tcp_res1:4,
                    tcp_cwr:1,
                    tcp_ece:1,
                    tcp_urg:1,
                    tcp_ack:1,
                    tcp_psh:1,
                    tcp_rst:1,
                    tcp_syn:1,
                    tcp_fin:1;

        pktword_n tcp_window;
        pktword_n tcp_check;
        pktword_n tcp_urg_ptr;

        int tcp_payload_len;
        pktbyte_n *tcp_payload;

    public:
        Tcp(Xpkt xpkt);
        Tcp();
        pktbyte_n *get_payload() { return tcp_payload; }
        int get_payload_len() { return tcp_payload_len; }
        pktword_n get_src() { return tcp_src; }
        pktword_n get_dst() { return tcp_dst; }
        pktdword_n get_seq() { return tcp_seq; }
        pktdword_n get_ack_seq() { return tcp_ack_seq; }
        void mangle_fin(pktword_n src, pktword_n dst, pktdword_n seq, pktdword_n ack_seq);
        void mangle_rst_ack(pktword_n src, pktword_n dst, pktdword_n seq, pktdword_n ack_seq);
        void append_payload(char *payload, int len);
        void set_checksum(Ip *ip);
        void assemble();
        void dissect();
};