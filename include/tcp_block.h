#include "tcp.h"

#define BLOCK_PAYLOAD 0

class Blockopt{
    private:
        int type;
        char *payload;
    public:
        Blockopt(std::string payload){ type = BLOCK_PAYLOAD, payload = payload;}
}

class TcpBlocker: public Agent{
    private:
        std::vector<Blockopt> blockopts;
    public:
        add_blockopt();
        block();
}