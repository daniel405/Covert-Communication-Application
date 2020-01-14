#include <pcap.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define SIZE_ETHERNET 14

// tcpdump header (ether.h) defines ETHER_HDRLEN)
#ifndef ETHER_HDRLEN
#define ETHER_HDRLEN 14
#endif

// Function Prototypes
u_int16_t handle_ethernet (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
void handle_IP (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
void handle_TCP (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
void print_payload (const u_char *, int);
void print_hex_ascii_line (const u_char *, int, int);


/*
 * Structure of an internet header, stripped of all options.
 *
 * This is taken directly from the tcpdump source
 *
 * We declare ip_len and ip_off to be short, rather than u_short
 * pragmatically since otherwise unsigned comparisons can result
 * against negative integers quite easily, and fail in subtle ways.
 */
struct pcap_ip {
								u_int8_t ip_vhl; /* header length, version */
#define IP_V(ip) (((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip) ((ip)->ip_vhl & 0x0f)
								u_int8_t ip_tos; /* type of service */
								u_int16_t ip_len; /* total length */
								u_int16_t ip_id; /* identification */
								u_int16_t ip_off; /* fragment offset field */
#define IP_DF 0x4000   /* dont fragment flag */
#define IP_MF 0x2000   /* more fragments flag */
#define IP_OFFMASK 0x1fff  /* mask for fragmenting bits */
								u_int8_t ip_ttl; /* time to live */
								u_int8_t ip_p; /* protocol */
								u_int16_t ip_sum; /* checksum */
								struct in_addr ip_src,ip_dst; /* source and dest address */
};

/* UDP header */
struct pcap_udp {
								u_short uh_sport;               /* source port */
								u_short uh_dport;               /* destination port */
								u_short uh_ulen;           /* udp length */
								u_short th_sum;                 /* checksum */
};

/* STCP header */
struct pcap_tcp {
 unsigned short int tcph_srcport;
 unsigned short int tcph_destport;
 unsigned int tcph_seqnum;
 unsigned int tcph_acknum;
 unsigned char tcph_reserved:4, tcph_offset:4;
 // unsigned char tcph_flags;
 unsigned int		 tcp_res1:4; /*little-endian*/
 unsigned int		 tcph_hlen:4; /*length of tcp header in 32-bit words*/
 unsigned int		 tcph_fin:1; /*Finish flag "fin"*/
 unsigned int		 tcph_syn:1; /*Synchronize sequence numbers to start a connection*/
 unsigned int		 tcph_rst:1; /*Reset flag */
 unsigned int		 tcph_psh:1; /*Push, sends data to the application*/
 unsigned int		 tcph_ack:1; /*acknowledge*/
 unsigned int		 tcph_urg:1; /*urgent pointer*/
 unsigned int		 tcph_res2:2;
 unsigned short int tcph_win;
 unsigned short int tcph_chksum;
 unsigned short int tcph_urgptr
};
