#include "utils.h"

void get_dev_info(struct net_info *ninfo){
    int s;
    struct ifreq ifr;
    char errbuf[PCAP_ERRBUF_SIZE];

    s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, ninfo->dev, IFNAMSIZ);

    ioctl(s, SIOCGIFHWADDR, &ifr);
    memcpy(ninfo->dev_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    ioctl(s, SIOCGIFADDR, &ifr);
    memcpy(ninfo->dev_ip, ifr.ifr_addr.sa_data + 2, 4);
}

void mac_ntop(char *mac, char *mac_s){
    int len = 0;

    for(int i=0; i<ETH_ALEN; i++){
        sprintf(mac_s+len, "%02X", (unsigned char)mac[i]);
        
        if(i != ETH_ALEN-1)
            strcat(mac_s,":");
        len += 3;
    }
}

#ifdef DEBUG
    void print_mac(char *mac, char *prefix){
        char mac_s[18];

        BZERO(mac_s, 18);

        if(prefix)
            printf("%s", prefix);

        mac_ntop(mac, mac_s);

        printf("mac: %s\n", mac_s);
    }

    void print_ip(char *ip, char *prefix){
        char ip_str[20];
        BZERO(ip_str, 20);

        if(prefix)
            printf("%s", prefix);

        inet_ntop(AF_INET, ip, ip_str, sizeof(ip_str));
        printf("IP: %s\n",ip_str);
    }

    void print_network_info(struct net_info *ninfo){
        printf("NIC: %s\n",ninfo->dev);
        print_ip(ninfo->dev_ip, "NIC ");
        print_mac(ninfo->dev_mac, "NIC ");
        print_ip(ninfo->ins_ip, "Inspector ");
        print_mac(ninfo->ins_mac, "Inspector ");
        print_ip(ninfo->app_ip, "App ");
        print_mac(ninfo->app_mac, "App ");
        print_ip(ninfo->gw_ip, "Gateway ");
        print_mac(ninfo->gw_mac, "Gateway ");
    }
#endif

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

void grab_network_info(struct net_info *ninfo){
    get_dev_info(ninfo);
    get_target_hw(ninfo->handle, ninfo, ninfo->ins_ip, ninfo->ins_mac);
    get_target_hw(ninfo->handle, ninfo, ninfo->app_ip, ninfo->app_mac);
    get_target_hw(ninfo->handle, ninfo, ninfo->gw_ip, ninfo->gw_mac);
}
