#include "tcp_block.h"

void TcpBlocker::add_blockopt(std::string host){
    Blockopt opt = Blockopt(host);

    blockopts.push_back(opt);
}

bool TcpBlocker::match_host(std::string payload, std::string block_host){
    if(payload.find("Host: " + block_host) != std::string::npos){
        return true;
    }
    else
        return false;
}

void TcpBlocker::block(){
    auto opt_iter = blockopts.begin();
    char errbuf[PCAP_ERRBUF_SIZE];
    const char * pcap_filter = "tcp dst port 80";
    pcap_t *handle = pcap_open_live(get_dev().c_str(), BUFSIZ, 1, 1000, errbuf);
    struct pcap_pkthdr *header;
    const pktbyte_n *packet;
    int block_type;
    std::string payload;

    if(handle == NULL){
        std::cerr << "couldn't open device " << this->get_dev() << ":" << errbuf << std::endl;
        exit(-1);
    }

    set_pcap_filter(handle, const_cast<char*>(pcap_filter), *(reinterpret_cast<bpf_u_int32*>(this->get_ip())));
    while(1){
        int res = pcap_next_ex(handle, &header, &packet);

        if(res == 0) continue;
        if(res == -1 || res == -2) break;

        Xpkt xpkt = Xpkt(const_cast<pktbyte_n *>(packet), header->len);
        Tcp tcp_pkt = Tcp(xpkt);

        if(tcp_pkt.get_payload_len())
            payload = reinterpret_cast<char*>(tcp_pkt.get_payload());
        else
            payload = "";

        for(opt_iter=blockopts.begin(); opt_iter<blockopts.end(); opt_iter++){
            block_type = opt_iter->get_type();
            switch(block_type){
                case BLOCK_HOST:
                    if(payload == ""){
                        continue;
                    }
                    else{
                        if(match_host(payload, opt_iter->get_host())){
                            close_conn(&xpkt);
                        }
                        break;
                    }
            }
        }
    }
}

void TcpBlocker::close_conn(Xpkt *xpkt){
    Ether eth = Ether(*xpkt);
    Ip ip = Ip(*xpkt);
    Tcp tcp = Tcp(*xpkt);
    
    std::cout << "backward" << std::endl;
    Ether backward_closer_eth = Ether(eth.get_src(), eth.get_dst(), ETH_P_IP);
    Ip backward_closer_ip = Ip(IPPROTO_TCP, ip.get_daddr(), ip.get_saddr());
    Tcp backward_closer_tcp = Tcp();
    backward_closer_tcp.mangle_fin(
        tcp.get_dst(),
        tcp.get_src(),
        tcp.get_ack_seq(),
        tcp.get_seq()+htonl(tcp.get_payload_len())
    );
    backward_closer_tcp.append_payload(const_cast<char*>(WARNING), strlen(WARNING));
    backward_closer_tcp.set_checksum(&backward_closer_ip);
    backward_closer_ip.set_tot_len(IP_HLEN + TCP_HLEN + strlen(WARNING));
    backward_closer_ip.set_checksum();
    Xpkt backward_closer = backward_closer_eth / backward_closer_ip / backward_closer_tcp;
    backward_closer.hexdump(ALL);
    TcpBlocker::send(&backward_closer);

    std::cout << "forward" << std::endl;
    Ether forward_closer_eth = Ether(eth.get_dst(), eth.get_src(), ETH_P_IP);
    Ip forward_closer_ip = Ip(IPPROTO_TCP, ip.get_saddr(), ip.get_daddr());
    Tcp forward_closer_tcp = Tcp();
    forward_closer_tcp.mangle_rst_ack(
        tcp.get_src(),
        tcp.get_dst(),
        tcp.get_seq(),
        tcp.get_ack_seq()
    );
    forward_closer_tcp.set_checksum(&forward_closer_ip);
    forward_closer_ip.set_tot_len(IP_HLEN + TCP_HLEN);
    forward_closer_ip.set_checksum();
    Xpkt forward_closer = forward_closer_eth / forward_closer_ip / forward_closer_tcp;
    forward_closer.hexdump(ALL);
    TcpBlocker::send(&forward_closer);
}