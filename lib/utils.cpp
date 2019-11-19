#include "utils.h"

/*
http://community.onion.io/topic/2441/obtain-the-mac-address-in-c-code/2
*/
void get_dev_info(std::string dev, pktbyte_n *mac, pktbyte_n *ip)
{
    int s;
    struct ifreq ifr;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, dev.c_str(), IFNAMSIZ);

    ioctl(s, SIOCGIFHWADDR, &ifr);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    ioctl(s, SIOCGIFADDR, &ifr);
    memcpy(ip, ifr.ifr_addr.sa_data + 2, 4);
}

void print_mac(pktbyte_n *mac, std::string prefix){
    std::cout << prefix << "MAC: ";

    std::ios_base::fmtflags f( std::cout.flags() );

    for(int i=0; i < ETH_ALEN; i++){
        std::cout 
        << std::hex 
        << std::setw(2) 
        << std::setfill('0') 
        << static_cast<int>(mac[i]);
        
        if(i != ETH_ALEN-1){
            std::cout << ":";
        }
    }
    std::cout << std::endl;

    std::cout.flags(f);
}

void parse_mac(pktbyte_n *mac, std::string *mac_str){
    std::stringstream ss;
    ss << std::hex;

    for(int i=0; i< ETH_ALEN; i++){
        ss << std::setw(2) << std::setfill('0') << static_cast<int>(mac[i]);

        if(i!=ETH_ALEN-1)
            ss << ':';
    }
    *mac_str = ss.str();
}

void print_ip(pktbyte_n *ip, std::string prefix){
    char ip_str[20];

    inet_ntop(AF_INET, ip, ip_str, sizeof(ip_str));
    std::cout << prefix << "IP: " << ip_str;
}

void parse_ip(pktbyte_n *ip, std::string *ip_str){
    char ip_str_ch[20];
    const char *res = inet_ntop(AF_INET, ip, ip_str_ch, sizeof(ip_str_ch));

    if(res == NULL){
        std::cerr << "IP is invalid" << std::endl;
        exit(-1);
    }

    *ip_str = std::string(ip_str_ch);
}

//Ref: http://www.microhowto.info/howto/calculate_an_internet_protocol_checksum_in_c.html#idp22656
uint16_t calc_checksum(void* vdata,size_t length) {
    // Cast the data pointer to one that can be indexed.
    char* data=(char*)vdata;

    // Initialise the accumulator.
    uint32_t acc=0xffff;

    // Handle complete 16-bit blocks.
    for (size_t i=0;i+1<length;i+=2) {
        uint16_t word;
        memcpy(&word,data+i,2);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Handle any partial block at the end of the data.
    if (length&1) {
        uint16_t word=0;
        memcpy(&word,data+length-1,1);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Return the checksum in network byte order.
    return htons(~acc);
}