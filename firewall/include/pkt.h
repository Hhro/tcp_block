#pragma once

#include "utils.h"

int set_pcap_filter(pcap_t *handle, char *filter, bpf_u_int32 net);
int send_pkt(pcap_t *handle, char *pkt, int len);
