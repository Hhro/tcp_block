#include "tcp_block.h"

TcpBlocker::add_blockopt(std::string payload){
    Blockopt opt = Blockopt(payload);

    blockopts.push_back(opt);
}

TcpBlocker::block(){
    auto opt_iter = blockopts.begin();
    char errbuf[PCAP_ERRBUF_SIZE];
    const char * pcap_filter = "arp and (arp[6:2] = 1)";
    pcap_t *handle = pcap_open_live(get_dev().c_str(), BUFSIZ, 1, 1000, errbuf);
    struct pcap_pkthdr *header;
    const pktbyte_n *packet;

    if(handle == NULL){
        std::cerr << "couldn't open device " << this->get_dev() << ":" << errbuf << std::endl;
        exit(-1);
    }

    while(1){
        set_pcap_filter(handle, const_cast<char*>(pcap_filter), *(reinterpret_cast<bpf_u_int32*>(this->get_ip())));
        int res = pcap_next_ex(handle, &header, &packet);

        if(res == 0) continue;
        if(res == -1 || res == -2) break;

        Xpkt xpkt = Xpkt(const_cast<pktbyte_n *>(packet), header->len);
        Tcp tcp_pkt = Tcp(xpkt);

        for(opt_iter=blockopts.begin(); opt_iter<blockopts.end(); opt_iter++){
            if(tcp_pkt.payload)

        }
    }
}