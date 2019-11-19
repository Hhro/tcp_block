#include "tcp.h"

Tcp::Tcp(Xpkt xpkt) : Xpkt(xpkt){
    Tcp::dissect();
}

Tcp::Tcp() : Xpkt(){
}

void Tcp::mangle_fin(pktword_n src, pktword_n dst, pktdword_n seq, pktdword_n ack_seq){
    struct tcphdr tcp;
    BZERO(&tcp, TCP_HLEN);

    tcp.source = src;
    tcp.dest = dst;
    tcp.seq = seq;
    tcp.ack_seq = ack_seq;
    tcp.doff = TCP_HLEN / 4;
    tcp.fin = 1;
    tcp.check = 0;

    Xpkt::set_pktbuf(reinterpret_cast<pktbyte_n*>(&tcp), TCP_HLEN);
    dissect();
}

void Tcp::mangle_rst_ack(pktword_n src, pktword_n dst, pktdword_n seq, pktdword_n ack_seq){
    struct tcphdr tcp;
    BZERO(&tcp, TCP_HLEN);

    tcp.source = src;
    tcp.dest = dst;
    tcp.seq = seq;
    tcp.ack_seq = ack_seq;
    tcp.doff = TCP_HLEN / 4;
    tcp.ack = 1;
    tcp.rst = 1;

    Xpkt::set_pktbuf(reinterpret_cast<pktbyte_n*>(&tcp), TCP_HLEN);
    dissect();
}

void Tcp::append_payload(char *payload, int len){
    tcp_payload_len = len; 
    tcp_payload = get_pktbuf() + tcp_doff * 4;

    Tcp::append(reinterpret_cast<pktbyte_n*>(payload), len);
}

void Tcp::assemble(){
    pktword_n tmp;

    Tcp::append(WPTR_TO_BPTR(&tcp_src), WORD);
    Tcp::append(WPTR_TO_BPTR(&tcp_dst), WORD);
    Tcp::append(DPTR_TO_BPTR(&tcp_seq), DWORD);
    Tcp::append(DPTR_TO_BPTR(&tcp_ack_seq), DWORD);

    tmp =   tcp_doff        |
            tcp_res1 << 4   |
            tcp_cwr << 8    |
            tcp_ece << 9    |
            tcp_urg << 10   |
            tcp_ack << 11   |
            tcp_psh << 12   |
            tcp_rst << 13   |
            tcp_syn << 14   |
            tcp_fin << 15;
    
    Tcp::append(WPTR_TO_BPTR(&tmp), WORD);
    Tcp::append(WPTR_TO_BPTR(&tcp_window), WORD);
    Tcp::append(WPTR_TO_BPTR(&tcp_check), WORD);
    Tcp::append(WPTR_TO_BPTR(&tcp_urg_ptr), WORD);

    if(tcp_payload && tcp_payload_len != 0)
        Tcp::append(tcp_payload, tcp_payload_len);
}

void Tcp::set_checksum(Ip *ip){
    struct tcphdr *tcp = reinterpret_cast<struct tcphdr*>(get_pktbuf());
    struct pseudo_ip pip;
    int completed_len = sizeof(struct pseudo_ip) + get_len();
    pktbyte_n *completed = (pktbyte_n*)calloc(completed_len, 1);

    tcp->check = 0;
    memcpy(&pip.daddr, ip->get_daddr(), 4);
    memcpy(&pip.saddr, ip->get_saddr(), 4);
    pip.reserved = 0;
    pip.protocol = IPPROTO_TCP;
    pip.size = htons(get_len());

    memcpy(completed, &pip, sizeof(pip));
    memcpy(completed + sizeof(pip), get_pktbuf(), get_len());

    tcp_check = calc_checksum(completed, completed_len);
    tcp->check = tcp_check;

    free(completed);
}

void Tcp::dissect(){
    iphdr *ip = IP(get_pktbuf());
    tcphdr *tcp = TCP(get_pktbuf());

    tcp_src = tcp->source;
    tcp_dst = tcp->dest;
    tcp_seq = tcp->seq;
    tcp_ack_seq = tcp->ack_seq;
    tcp_res1 = tcp->res1;
    tcp_doff = tcp->doff;
    tcp_fin = tcp->fin;
    tcp_syn = tcp->syn;
    tcp_rst = tcp->rst;
    tcp_psh = tcp->psh;
    tcp_ack = tcp->ack;
    tcp_urg = tcp->urg;
    tcp_ece = tcp->ece;
    tcp_cwr = tcp->cwr;
    tcp_window = tcp->window;
    tcp_check = tcp->check;
    tcp_urg_ptr = tcp->urg_ptr;

    tcp_payload_len = ip->tot_len - (ip->ihl + tcp_doff) * 4;

    if(tcp_payload_len)
        tcp_payload = reinterpret_cast<pktbyte_n*>(tcp) + (tcp_doff * 4);
    else
        tcp_payload = nullptr;
}