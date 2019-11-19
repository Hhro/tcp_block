#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <pthread.h>
#include <pcap.h>

#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/libnetfilter_queue_udp.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#define bool int
#include <libnetfilter_queue/pktbuff.h>
#undef bool

#include "pkt.h"
#include "ether.h"
#include "ip.h"
#include "arp.h"
#include "tcp.h"
#include "utils.h"
#include "udp.h"

#define ALERT "You can't get anything from me LOL :) Just listen to what I say. Once upon a time, there was a widow who had a lazy son called Jack. They....zzzzzzzzzzzz. Nah, just go away!"

struct nfq_handles{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
};

void report_malpkt(struct net_info *ninfo, struct pkt_buff *pkt);
void close_conn(struct net_info *ninfo, struct pkt_buff *pkt);
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *ninfo);
static int out_app_handle(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
            struct nfq_data *nfa, void *ninfo);
static int ins_out_handle(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
            struct nfq_data *nfa, void *ninfo);
void init_firewall(char *ins_ip, char *app_ip, char *gw_ip);
void init_nfq(struct nfq_handles *nfq, int num, int (*cb)(struct nfq_q_handle*, struct nfgenmsg*, struct nfq_data*, void*), void *arg);
void fini_nfq(struct nfq_handles *nfq);
void send_alert(struct net_info *ninfo, struct pkt_buff *pkt);

