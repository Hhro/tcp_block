#include <pcap.h>
#include "pkt.h"

int set_pcap_filter(pcap_t *handle, char *filter, bpf_u_int32 net){
    struct bpf_program fp;
    
    if(pcap_compile(handle, &fp, filter, 0, net) == -1) {
        fprintf(stderr, "[-] Can't parse filter \'%s\'\n==> %s\n", filter, pcap_geterr(handle));
        return -1;
    }

    if(pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "[-] Can't install filter \'%s\'\n==>%s\n", filter, pcap_geterr(handle));
        return -1;
    }
}

int send_pkt(pcap_t *handle, char *pkt, int len){
    if(pcap_inject(handle, pkt, len) < 0){
        pcap_perror(handle, "send: ");
        return -1;
    }

    return 0;
}