#include <cstdint>
#include <arpa/inet.h>
#include "iphdr.h"

#pragma pack(push, 1)
struct TcpHdr final {
    static uint16_t calcChecksum(IpHdr* ipHdr, TcpHdr* tcpHdr);

    u_int16_t sp_;
    u_int16_t dp_;
    u_int32_t sq_;
    u_int32_t ack_;
    u_char off_;
    u_int8_t flags_;
    u_int16_t window_;
    u_int16_t chksum_;
    u_int16_t ugptr;

    u_int16_t dp() { return ntohs(dp_); }
    uint32_t sq() { return ntohl(sq_); }
    u_int8_t off() { return off_; }
    uint16_t sum() { return ntohs(chksum_); }

    enum: u_int16_t{
        HTTP = 80,
        HTTPS = 443
    };
    enum: u_int8_t{
        FIN = 1<<0,
        SYN = 1<<1,
        RST = 1<<2,
        PSH = 1<<3,
        ACK = 1<<4,
        URG = 1<<5,
    };
};
#pragma pack(pop)