#include "firewall.h"

char mal_chars[] = " !\"#$%%&\'()*+,-./:;<=>?@[\\]^_`{|}~";

void report_malpkt(struct net_info *ninfo, struct pkt_buff *pkt){
    struct ethhdr report_eth;
    struct iphdr report_ip;
    struct udphdr report_udp;
    struct iphdr *ip;
    struct tcphdr *tcp;
    int tcp_payload_len;
    int report_len;
    char *tcp_payload;
    pcap_t *handle = ninfo->handle;

    ip = nfq_ip_get_hdr(pkt);
    tcp = nfq_tcp_get_hdr(pkt);
    tcp_payload = nfq_tcp_get_payload(tcp, pkt);
    tcp_payload_len = nfq_tcp_get_payload_len(tcp, pkt) - tcp->doff*4;
    report_len = ETH_HLEN + IP_HLEN + TCP_HLEN + tcp_payload_len;

    char *report_pkt = (char*)calloc(sizeof(char) * report_len, 1);

    BZERO(&report_eth, sizeof(struct ethhdr));
    BZERO(&report_ip, sizeof(struct iphdr));
    BZERO(&report_udp, sizeof(struct udphdr));

    //Mangle ethernet header
    //dst: inspector MAC, src: device MAC
    mangle_ether(ninfo->ins_mac, ninfo->dev_mac, &report_eth);

    //Mangle IP header
    //src: original src IP, dst: inspector IP, proto: UDP
    //tot_len: IP_HELN + TCP_HLEN + tcp_payload_len
    mangle_ip((char*)&ip->saddr, ninfo->ins_ip, IPPROTO_UDP, tcp_payload_len, &report_ip);
    set_ip_checksum(&report_ip, IP_HLEN);

    // Mangle UDP header
    //src: original src port, dst: original dst port
    //len: UDP_HLEN + tcp_payload_len
    mangle_udp(tcp->source, tcp->dest, htons(UDP_HLEN+tcp_payload_len), &report_udp);

    // Assemble
    memcpy(report_pkt, &report_eth, ETH_HLEN);
    memcpy(report_pkt + ETH_HLEN, &report_ip, report_ip.ihl*4);
    memcpy(report_pkt + ETH_HLEN + IP_HLEN, &report_udp, UDP_HLEN);
    memcpy(report_pkt + ETH_HLEN + IP_HLEN + UDP_HLEN, tcp_payload, tcp_payload_len);

    if(pcap_sendpacket(handle, report_pkt, report_len)){
        pcap_perror(handle, "send: ");
        free(report_pkt);
    };

    free(report_pkt);
}

void close_conn(struct net_info *ninfo, struct pkt_buff *pkt){
    struct iphdr *ip;
    struct tcphdr *tcp;
    pcap_t *handle = ninfo->handle;
    int tcp_payload_len;

    char *src_closer = (char*)calloc(sizeof(char) * ETH_HLEN + IP_HLEN + TCP_HLEN, 1);
    char *dst_closer = (char*)calloc(sizeof(char) * ETH_HLEN + IP_HLEN + TCP_HLEN, 1);

    ip = nfq_ip_get_hdr(pkt);
    tcp = nfq_tcp_get_hdr(pkt);
    tcp_payload_len = nfq_tcp_get_payload_len(tcp, pkt) - tcp->doff * 4;

    //Mangle RST/ACK packet for source & destination
    mangle_closer(          
        ninfo->dev_mac,                  //Ether src MAC: device MAC
        ninfo->gw_mac,                   //Ether dst MAC: gateway MAC
        ninfo->dev_ip,                   //IP src IP: device IP
        (char*)&ip->saddr,               //IP dst IP: sender IP
        tcp->dest,                       //TCP dport: dport
        tcp->source,                     //TCP sport: sport
        tcp->ack_seq,                    //TCP seq number: ack
        tcp->seq+htonl(tcp_payload_len), //TCP ack number: seq + len(tcp_payload)
        src_closer
    );
    mangle_closer(
        ninfo->dev_mac,                  //Ether src MAC: device MAC
        ninfo->app_mac,                  //Ether dst MAC: app MAC
        ninfo->dev_ip,                   //IP src IP: device ip
        ninfo->app_ip,                   //IP dst IP: app ip
        tcp->source,                     //TCP sport: sport
        tcp->dest,                       //TCP dport: dport
        tcp->seq,                        //TCP seq number: seq
        tcp->ack_seq,                    //TCP ack number: ack
        dst_closer
    );

    //Send RST/ACK packet to source & destination. 
    //TCP connection would be closed.
    send_pkt(handle, src_closer, ETH_HLEN + 40);
    send_pkt(handle, dst_closer, ETH_HLEN + 40);

    free(src_closer);
    free(dst_closer);
}


void send_alert(struct net_info *ninfo, struct pkt_buff *pkt){
    struct ethhdr alert_eth;
    struct iphdr alert_ip;
    struct udphdr alert_udp;
    struct iphdr *ip;
    struct udphdr *udp;
    int alert_len;
    int udp_payload_len;
    char *alert_pkt;
    char *udp_payload;

    pcap_t *handle = ninfo->handle;

    ip = nfq_ip_get_hdr(pkt);
    udp = nfq_udp_get_hdr(pkt);
    udp_payload_len = strlen(ALERT);
    alert_len = ETH_HLEN + IP_HLEN + UDP_HLEN + strlen(ALERT);

    alert_pkt = (char*)calloc(sizeof(char) * alert_len, 1);    

    BZERO(&alert_eth, sizeof(struct ethhdr));
    BZERO(&alert_ip, sizeof(struct iphdr));
    BZERO(&alert_udp, sizeof(struct udphdr));
    
    //Mangle ethernet header
    //dst: gateway MAC, src: device MAC
    mangle_ether(ninfo->gw_mac, ninfo->dev_mac, &alert_eth);

    //Mangle IP header
    //src: device IP, dst: original dst, protocol: UDP, 
    //tot_len: IP_HLEN + UDP_HLEN + udp_payload_len
    mangle_ip(ninfo->dev_ip, (char*)&ip->daddr, IPPROTO_UDP, udp_payload_len, &alert_ip);
    set_ip_checksum(&alert_ip, IP_HLEN);

    //Mangle UDP header
    udp->check = 0;
    set_udp_checksum(&alert_ip, udp, ntohs(udp->len));
    memcpy(&alert_udp, udp, UDP_HLEN);

    //Assemble
    memcpy(alert_pkt, &alert_eth, ETH_HLEN);
    memcpy(alert_pkt + ETH_HLEN, &alert_ip, IP_HLEN);
    memcpy(alert_pkt + ETH_HLEN + IP_HLEN, &alert_udp, UDP_HLEN);
    memcpy(alert_pkt + ETH_HLEN + IP_HLEN + UDP_HLEN, ALERT, strlen(ALERT));

    if(pcap_sendpacket(handle, alert_pkt, alert_len)){
        pcap_perror(handle, "send: ");
        free(alert_pkt);
    };

    free(alert_pkt);
}

static int out_app_handle(
    struct nfq_q_handle *qh, 
    struct nfgenmsg *nfmsg,
    struct nfq_data *nfa, 
    void *ninfo
){
    struct nfqnl_msg_packet_hdr *ph;
    struct pkt_buff *pkt;
    struct tcphdr* tcp;
    struct iphdr* ip;
    int id;
    int payload_len;
    int tcp_payload_len;
    uint8_t *payload;
    uint8_t *tcp_payload;
    int mal_chars_len = strlen(mal_chars);

    ph = nfq_get_msg_packet_hdr(nfa);
    id = ntohl(ph->packet_id);

    //Get TCP header
    payload_len=nfq_get_payload(nfa, &payload);
    pkt = pktb_alloc(AF_INET, payload, payload_len, 0);
    ip = nfq_ip_get_hdr(pkt);
    nfq_ip_set_transport_header(pkt, ip);
    tcp = nfq_tcp_get_hdr(pkt);

    //Filter TCP packet
    if(tcp){
        tcp_payload_len=nfq_tcp_get_payload_len(tcp, pkt) - tcp->doff * 4;
        if(tcp_payload_len>0){
            tcp_payload=(uint8_t *)nfq_tcp_get_payload(tcp,pkt);
            //If packet has malicious byte
            for(int i=0; i<mal_chars_len; i++){
                if(memchr((char*)tcp_payload, mal_chars[i], tcp_payload_len)){
                    goto DROP;
                }
            }
        }
    }

ACCEPT:
    pktb_free(pkt);
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    
DROP:
    close_conn(ninfo, pkt);   //Close TCP connection
    report_malpkt(ninfo, pkt); //Send TCP payload to inspector with UDP
    pktb_free(pkt);
    return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
}

static int ins_out_handle(
    struct nfq_q_handle *qh, 
    struct nfgenmsg *nfmsg,
    struct nfq_data *nfa, 
    void *ninfo
    )
{
    struct nfqnl_msg_packet_hdr *ph;
    struct pkt_buff *pkt;
    struct udphdr* udp;
    struct iphdr* ip;
    uint8_t *payload;
    uint8_t *udp_payload;
    int payload_len, udp_payload_len;
    int id = 0;

    ph = nfq_get_msg_packet_hdr(nfa);
    id = ntohl(ph->packet_id);

    //Get UDP header of pkt
    payload_len = nfq_get_payload(nfa, &payload);
    pkt = pktb_alloc(AF_INET, payload, payload_len, 0);
    ip = nfq_ip_get_hdr(pkt);
    nfq_ip_set_transport_header(pkt, ip);
    udp = nfq_udp_get_hdr(pkt);

    //Send alert to UDP pkt's destination
    if(udp){
        udp_payload_len = nfq_udp_get_payload_len(udp, pkt) - UDP_HLEN;
        if(udp_payload_len > 0){
            udp_payload = pktb_transport_header(pkt) + sizeof(struct udphdr);
            send_alert(ninfo, pkt);
        }
    }

    pktb_free(pkt);

    //Always drop outbound udp packet
    return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
}

static void *receiver(void *nfq_in)
{
    struct nfq_handles *nfq = (struct nfq_handles *)nfq_in;
    int rv;
    char buf[4096];

    BZERO(buf, 4096);

    for (;;) {
        if ((rv = recv(nfq->fd, buf, sizeof(buf), 0)) >= 0) {
                nfq_handle_packet(nfq->h, buf, rv); /* send packet to callback */
                continue;
        }
    }
}

void init_nfq(struct nfq_handles *nfq, int num, int (*cb)(struct nfq_q_handle*, struct nfgenmsg*, struct nfq_data*, void*), void *arg){
    nfq->h = nfq_open();

    if (!nfq->h) {
        exit(1);
    }

    nfq->qh = nfq_create_queue(nfq->h, num, cb, arg);
    if (!nfq->qh) {
        exit(1);
    }

    if (nfq_set_mode(nfq->qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        exit(1);
    }

    nfq->fd = nfq_fd(nfq->h);
}

void fini_nfq(struct nfq_handles *nfq){
    nfq_destroy_queue(nfq->qh);
    nfq_close(nfq->h);
}

void init_firewall(char *ins_ip, char *app_ip, char *gw_ip){
    int rv;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct nfq_handles nfq_out_app;
    struct nfq_handles nfq_ins_out;
    struct net_info *ninfo = (struct net_info*)calloc(sizeof(struct net_info), 1);
    pthread_t out_app_tid;
    pthread_t ins_out_tid;

    inet_pton(AF_INET, ins_ip, ninfo->ins_ip);
    inet_pton(AF_INET, app_ip, ninfo->app_ip);
    inet_pton(AF_INET, gw_ip, ninfo->gw_ip);

    //Grab network information
    ninfo->dev = pcap_lookupdev(errbuf);
    ninfo->handle = pcap_open_live(ninfo->dev, BUFSIZ, 1, 1000, errbuf);
    grab_network_info(ninfo);

    #ifdef DEBUG
        print_network_info(ninfo);
    #endif

    //Initialize NFQ for outbound->app and inspector->outbound traffic
    init_nfq(&nfq_out_app, 0, out_app_handle, ninfo);
    init_nfq(&nfq_ins_out, 1, ins_out_handle, ninfo);

    //Create packet receiver for NFQs
    pthread_create(&out_app_tid, NULL, receiver, &nfq_out_app);
    pthread_create(&ins_out_tid, NULL, receiver, &nfq_ins_out);

    pthread_join(out_app_tid, NULL);
    pthread_join(ins_out_tid, NULL);

    //Finalize NFQs
    fini_nfq(&nfq_out_app);
    fini_nfq(&nfq_ins_out);

    pcap_close(ninfo->handle);

    free(ninfo);
}
