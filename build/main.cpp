#include <iostream>
#include <vector>
#include <arpa/inet.h>
#include "tcp_block.h"

void usage(){
    std::cout << "Usage: ./tcp_block <interface> <host>" << std::endl;
    std::cout << "Example: ./tcp_block wlan0 test.gilgil.net" << std::endl;
}

int main(int argc, char *argv[]){
    if(argc < 3){
        usage();
        exit(-1);
    }

    std::string interface = argv[1];
    std::string host = argv[2];
    TcpBlocker blocker = {"hhro", interface};

    std::cout << "[Interface] "
              << "Adapter: " << interface << std::endl;

    blocker.add_blockopt(host);
    blocker.block();
    std::cout << std::endl;
}
