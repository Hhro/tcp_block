#include <string>
#include <vector>
#include "agent.h"
#include "tcp.h"

#define BLOCK_HOST 0

#define WARNING "HTTP/1.1 302 Redirect\r\nLocation: http://www.warning.or.kr\r\n\r\n"

class Blockopt{
    private:
        int type;
        std::string host;
    public:
        Blockopt(std::string host){ type = BLOCK_HOST, this->host = host; }
        int get_type() { return type; }
        std::string get_host() { return host; }
};

class TcpBlocker: public Agent{
    private:
        std::vector<Blockopt> blockopts;
    public:
        TcpBlocker(std::string name, std::string dev) : Agent(name, dev) {}
        void add_blockopt(std::string host);
        bool match_host(std::string payload, std::string block_host);
        void close_conn(Xpkt *xpkt);
        void block();
};