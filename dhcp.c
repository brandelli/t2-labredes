#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>  //estrutura ifr
#include <netinet/ether.h> //header ethernet
#include <netinet/in.h> //definicao de protocolos
#include <arpa/inet.h> //funcoes para manipulacao de enderecos IP
#include <netinet/in_systm.h> //tipos de dados
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>

#define BUFFSIZE 1518

#define DEST_MAC0	0x00
#define DEST_MAC1	0x00
#define DEST_MAC2	0x00
#define DEST_MAC3	0x00
#define DEST_MAC4	0x00
#define DEST_MAC5	0x00

#define SRC_MAC0	0xb4
#define SRC_MAC1  0xb6
#define SRC_MAC2  0x76
#define SRC_MAC3  0x43
#define SRC_MAC4  0x8d
#define SRC_MAC5  0x2a

#define DHCP_DISCOVER 1
#define DHCP_OFFER    2
#define DHCP_REQUEST  3
#define DHCP_ACK      5
   
unsigned char buff1[BUFFSIZE]; // buffer de recepcao

int sockd;
int on;
struct ifreq ifr;
struct ifreq if_idx;
struct ifreq if_ip;
struct ifreq if_mac;
struct boothdr
{
   char msg_type;
   char hdr_type;
   char hdr_len;
   char hops;
   int transaction_id;
   short seconds;
   short flags;
   float client_ip;
   float your_ip;
   float next_server_ip;
   float relay_agent_ip;
   char client_mac[16];
   char server_host_name[64];
   char bootfile_name[128];
   char options[64];
};

void print_ip(int ip)
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;   
    printf("%d.%d.%d.%d\n", bytes[0], bytes[1], bytes[2], bytes[3]);        
}

void print_transaction_id(int transaction_id)
{
   unsigned char bytes[4];
   bytes[0] = transaction_id & 0xFF;
   bytes[1] = (transaction_id >> 8) & 0xFF;
   bytes[2] = (transaction_id >> 16) & 0xFF;
   bytes[3] = (transaction_id >> 24) & 0xFF;   
   printf("0x%x%x%x%x\n", bytes[0], bytes[1], bytes[2], bytes[3]);
}

unsigned short in_cksum(unsigned short *addr,int len)
{
        register int sum = 0;
        u_short answer = 0;
        register u_short *w = addr;
        register int nleft = len;

        /*
         * Our algorithm is simple, using a 32 bit accumulator (sum), we add
         * sequential 16 bit words to it, and at the end, fold back all the
         * carry bits from the top 16 bits into the lower 16 bits.
         */
        while (nleft > 1)  {
                sum += *w++;
                nleft -= 2;
        }

        /* mop up an odd byte, if necessary */
        if (nleft == 1) {
                *(u_char *)(&answer) = *(u_char *)w ;
                sum += answer;
        }

        /* add back carry outs from top 16 bits to low 16 bits */
        sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
        sum += (sum >> 16);                     /* add carry */
        answer = ~sum;                          /* truncate to 16 bits */
        return(answer);
}

int main(int argc,char *argv[])
{
   struct ether_header *eh = (struct ether_header *) buff1;
   struct iphdr *iph = (struct iphdr *) (buff1 + sizeof(struct ether_header));
   struct udphdr *udph = (struct udphdr *) (buff1 + sizeof(struct iphdr) + sizeof(struct ether_header));
   struct boothdr *booth = (struct boothdr *) (buff1 + sizeof(struct udphdr) + sizeof(struct iphdr) + sizeof(struct ether_header));
   FILE *fp;
   char teste[] = "testinho";
   struct sockaddr_ll socket_address;
   int dhcp_status = DHCP_DISCOVER;
   if((sockd = socket(AF_PACKET, SOCK_RAW,  htons(ETH_P_ALL))) < 0) {
      printf("Erro na criacao do socket.\n");
      exit(1);
   }

   strcpy(ifr.ifr_name, "wlp2s0");
   if(ioctl(sockd, SIOCGIFINDEX, &ifr) < 0)
      printf("erro no ioctl!");
   ioctl(sockd, SIOCGIFFLAGS, &ifr);
   ifr.ifr_flags |= IFF_PROMISC;
   ioctl(sockd, SIOCSIFFLAGS, &ifr);
   ioctl(sockd, SIOCGIFADDR, &ifr);
   
   memset(&if_idx, 0, sizeof(struct ifreq));
   strncpy(if_idx.ifr_name, "wlp2s0", (int) strlen("wlp2s0"));
   if (ioctl(sockd, SIOCGIFINDEX, &if_idx) < 0)
       perror("SIOCGIFINDEX");
   memset(&if_mac, 0, sizeof(struct ifreq));
   strncpy(if_mac.ifr_name, "wlp2s0", (int) strlen("wlp2s0"));
   if (ioctl(sockd, SIOCGIFHWADDR, &if_mac) < 0)
       perror("SIOCGIFHWADDR");

   memset(&if_ip, 0, sizeof(struct ifreq));
   strncpy(if_ip.ifr_name, "wlp2s0", (int) strlen("wlp2s0"));
   if (ioctl(sockd, SIOCGIFADDR, &if_ip) < 0)
       perror("SIOCGIFADDR");
   
   printf("%s\n", inet_ntoa(( (struct sockaddr_in *)&ifr.ifr_addr )->sin_addr) );
	// recepcao de pacotes
	// recepcao de pacotes
   printf("meu ip");
   printf("%s\n", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
   print_ip((long)&ifr.ifr_addr);
   print_ip((long)&ifr.ifr_dstaddr);
   print_ip((long)&ifr.ifr_broadaddr);
   print_ip((long)&ifr.ifr_netmask);
   printf("%s\n", ifr.ifr_name);
   printf("Tamanho ethernet %ld\n",sizeof(struct ether_header));
   printf("Tamanho ip %ld\n",sizeof(struct iphdr));
   printf("Tamanho udp %ld\n",sizeof(struct udphdr));
   printf("Tamanho boot %ld\n",sizeof(struct boothdr));
   while (1) {
      switch (dhcp_status)
      {
         case DHCP_DISCOVER:
            while(dhcp_status == DHCP_DISCOVER){
               printf("teste\n");
               recv(sockd,(char *) &buff1, sizeof(buff1), 0x0); 
               if(iph->protocol == 17 && udph->source == htons(68) && udph->dest == htons(67)){
                  unsigned char option_code = booth->options[4] & 0xFF;
                  unsigned char option_type = booth->options[6] & 0xFF;
                  if(option_code == 53 && option_type == 1){
                     printf("DHCP_DISCOVER\n");
                     printf("IP Source: ");
                     print_ip(iph->saddr);
                     printf("IP Destiny: ");
                     print_ip(iph->daddr);

                     printf("UDP port source: %d \n", ntohs(udph->source));
                     printf("UDP port dest: %d \n", ntohs(udph->dest));
                     printf("Message Type: %d \n", booth->msg_type);
                     printf("hardware Type: %d \n", booth->hdr_type);
                     printf("hardware address length: %d \n", booth->hdr_len);
                     printf("hops: %d \n", booth->hops);
                     printf("transaction_id: ");
                     print_transaction_id(booth->transaction_id);
                     printf("option code: %d \n", option_code);
                     printf("option value: %d \n", option_type);
                     printf("--------------------------------------------------\n");
                     dhcp_status = DHCP_REQUEST;
                  }
               }
            }
         break;

         case DHCP_REQUEST:
            printf("DHCP_REQUEST \n");
            char *payload;
            eh->ether_dhost[0] = 0x00;
            eh->ether_dhost[1] = 0x00;
            eh->ether_dhost[2] = 0x00;
            eh->ether_dhost[3] = 0x00;
            eh->ether_dhost[4] = 0x00;
            eh->ether_dhost[5] = 0x00;
            eh->ether_shost[0] = SRC_MAC0;
            eh->ether_shost[1] = SRC_MAC1;
            eh->ether_shost[2] = SRC_MAC2;
            eh->ether_shost[3] = SRC_MAC3;
            eh->ether_shost[4] = SRC_MAC4;
            eh->ether_shost[5] = SRC_MAC5;
            eh->ether_type = htons(ETH_P_IP);
            iph->ihl = 5;
            iph->version = 4;
            iph->tos = 16;
            iph->id = htons(171);
            iph->ttl = 255;
            iph->protocol =  17;
            iph->frag_off = htons (0);
            iph->saddr = inet_addr(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
            iph->daddr = iph->saddr;
            iph->check = 0;
            iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + (int) strlen(teste));
            iph->check = in_cksum((unsigned short *)iph, sizeof(struct iphdr));
            udph->source = htons(3423);
            udph->dest = htons(5342);
            udph->check = 0;
            udph->len = htons(sizeof(struct udphdr) + (int) strlen(teste));
            payload = (char *) (buff1 + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr));
            strcpy(payload,teste);
            socket_address.sll_ifindex = if_idx.ifr_ifindex;
            socket_address.sll_halen = ETH_ALEN;
            socket_address.sll_addr[0] = DEST_MAC0;
            socket_address.sll_addr[1] = DEST_MAC1;
            socket_address.sll_addr[2] = DEST_MAC2;
            socket_address.sll_addr[3] = DEST_MAC3;
            socket_address.sll_addr[4] = DEST_MAC4;
            socket_address.sll_addr[5] = DEST_MAC5;
            int total_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr) + (int) strlen(teste);
            printf("total length: %d\n", total_len);
            if (sendto(sockd, buff1, total_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0){
               printf("Send failed\n");
               return 0;
            }
            dhcp_status = DHCP_OFFER;
         break;

         case DHCP_OFFER:
           printf("DHCP_OFFER\n");
           dhcp_status = DHCP_ACK;
         break;

         case DHCP_ACK:
           printf("DHCP_ACK\n");
           dhcp_status = 0;
         break;
      }
   }
}