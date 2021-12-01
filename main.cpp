#include <cstdio>
#include <errno.h>
#include <pcap.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <string.h>
#include <string>
#include <unistd.h>
#include <stdint.h>
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <thread>
#include <vector>
#include <mutex>
#include "ethhdr.h"
#include "tcphdr.h"

using namespace std;

#pragma pack(push, 1)
struct EthIpPacket final {
    EthHdr eth_;
    IpHdr ip_;
};
struct EthIpTcpPacket final {
    EthHdr eth_;
    IpHdr ip_;
    TcpHdr tcp_;
};
#pragma pack(pop)


void usage()
{
    cout << "syntax: ./tcp-block <interface> <pattern>\n";
    cout << "sample: ./tcp-block wlan0 \"Host: test.gilgil.net\"\n";
}


void IsSendError(int res, pcap_t *handle)
{
    if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}


void get_my_info(const char *interface, Mac* my_mac)
{
    int sockfd;
    struct ifreq ifr;
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0)
    {
        perror("[get_my_mac] socket: ");
        exit(0);
    }
    strcpy(ifr.ifr_name, interface);
    if(ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0)
    {
        perror("[get_my_info] mac-ioctl: ");
        close(sockfd);
        exit(-1);
    }
    memcpy(my_mac, ifr.ifr_hwaddr.sa_data, Mac::SIZE);
    close(sockfd);
}

u_int16_t checksum(u_int16_t *buffer, int size)
{
    u_int16_t cksum=0; 
    while(size >1) { 
        cksum += *buffer++; 
        size -= sizeof(u_int16_t);
    } 
    if(size) 
        cksum += *(u_int16_t*)buffer;

    cksum = (cksum >> 16) + (cksum & 0xffff); 
    cksum += (cksum >> 16); 
    return (u_int16_t)(~cksum); 
}


void packet_forward(EthIpTcpPacket* packet, EthIpTcpPacket* origin, Mac my_mac)
{
    int datasize = origin->ip_.len() - origin->ip_.hl() * 4 - origin->tcp_.off() * 4;

	packet->eth_.dmac_ = origin->eth_.dmac_;		     
	packet->eth_.smac_ = my_mac;		     
    
    packet->ip_.len_ = htons(sizeof(IpHdr) + sizeof(TcpHdr));
    packet->ip_.ttl_ = origin->ip_.ttl_;
    packet->ip_.sip_ = origin->ip_.sip_;
    packet->ip_.tip_ = origin->ip_.tip_;
    packet->ip_.sum_ = htons(IpHdr::calcChecksum(&(packet->ip_)));

    packet->tcp_.sp_ = origin->tcp_.sp_;
    packet->tcp_.dp_ = origin->tcp_.dp_;
    packet->tcp_.sq_ = htonl(origin->tcp_.sq() + datasize);
    packet->tcp_.ack_ = origin->tcp_.ack_;
    packet->tcp_.off_ = sizeof(TcpHdr) << 2;
    packet->tcp_.flags_ = TcpHdr::RST + TcpHdr::ACK;
    packet->tcp_.flags_ &= ~TcpHdr::SYN;
    packet->tcp_.chksum_ = htons(TcpHdr::calcChecksum(&(packet->ip_), &(packet->tcp_)));
	   
    return;
}


void packet_backward(EthIpTcpPacket* packet, EthIpTcpPacket* origin, Mac my_mac)
{
    int datasize = origin->ip_.len() - origin->ip_.hl() * 4 - origin->tcp_.off() * 4;

	packet->eth_.dmac_ = origin->eth_.smac();		     
	packet->eth_.smac_ = my_mac;		     

    packet->ip_.len_ = htons(sizeof(IpHdr) + sizeof(TcpHdr));
    packet->ip_.ttl_ = 128;
    packet->ip_.sip_ = origin->ip_.tip_;
    packet->ip_.tip_ = origin->ip_.sip_;
    packet->ip_.sum_ = htons(IpHdr::calcChecksum(&(packet->ip_)));

    packet->tcp_.sp_ = origin->tcp_.dp_;
    packet->tcp_.dp_ = origin->tcp_.sp_;
    packet->tcp_.sq_ = origin->tcp_.ack_;
	packet->tcp_.ack_ = htonl(origin->tcp_.sq() + datasize);
    packet->tcp_.off_ = sizeof(TcpHdr) << 2;
    packet->tcp_.flags_ = TcpHdr::RST + TcpHdr::ACK;
    packet->tcp_.flags_ &= ~TcpHdr::SYN;
    packet->tcp_.chksum_ = htons(TcpHdr::calcChecksum(&(packet->ip_), &(packet->tcp_)));

    return;
}


void block(pcap_t* handle, const char* pattern, Mac my_mac)
{
    while (true) {
		struct pcap_pkthdr* header;
		const u_char* p;
		int res = pcap_next_ex(handle, &header, &p);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
		}

        EthHdr *Eth = (EthHdr *)p;
        if(Eth->type() == EthHdr::Ip4){
            EthIpPacket* EthIp = (EthIpPacket *)p;
	        if(EthIp->ip_.pro() != IpHdr::TCP)
		        continue;

            EthIpTcpPacket* EthIpTcp = (EthIpTcpPacket *)p;
            if(EthIpTcp->tcp_.dp() != TcpHdr::HTTP && EthIpTcp->tcp_.dp() != TcpHdr::HTTPS)
                continue;

            unsigned char *buf = &(EthIpTcp->tcp_.off_);
	        u_int8_t offset = buf[0]>>2;
	        unsigned char *http = (unsigned char *)p + sizeof(EthHdr) + sizeof(IpHdr) + offset;

	        if(strncmp((char *)http, "GET", 3))
	        	continue;

	        char *text = strtok((char *)http, "\n");
	        while(text != NULL){
	        	if(strstr(text, pattern)){
                    // EthIpTcpPacket *Send;
                    std::cout << "[*] " << pattern << " blocked" << std::endl;
                    u_char Send[sizeof(EthIpTcpPacket)];
                    memcpy(Send, EthIpTcp, sizeof(EthIpTcpPacket));
                    packet_forward((EthIpTcpPacket *)Send, EthIpTcp, my_mac);
                    res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(Send), sizeof(EthIpTcpPacket));
	                IsSendError(res, handle);

                    memcpy(Send, EthIpTcp, sizeof(EthIpTcpPacket));
                    packet_backward((EthIpTcpPacket *)Send, EthIpTcp, my_mac);
                    res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(Send), sizeof(EthIpTcpPacket));
	                IsSendError(res, handle);
	        	}
	        	text = strtok(NULL, "\n");
	        }
        }
        else{
            continue;
        }
    }

}


int main(int argc, char *argv[])
{
    if(argc!=3)
    {
        usage();
        return 0;
    }

    const char* interface = argv[1];
    const char* pattern = argv[2];

    Mac my_mac;
    get_my_info(interface, &my_mac);

    char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
		exit(0);
	}

    block(handle, pattern, my_mac);

    return 0;
}