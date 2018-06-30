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
#define SRC_MAC1	0xb6
#define SRC_MAC2	0x76
#define SRC_MAC3	0x43
#define SRC_MAC4	0x8d
#define SRC_MAC5	0x2a

#define DHCP_DISCOVER 1
#define DHCP_OFFER    2
#define DHCP_REQUEST  3
#define DHCP_ACK      5
	
unsigned char buff1[BUFFSIZE]; // buffer de recepcao

int sockd;
int on;
struct ifreq ifr;
struct boothdr
{
   char msg_type;
   char hdr_type;
   char hdr_len;
   char hops;
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

int main(int argc,char *argv[])
{
	struct ether_header *eh = (struct ether_header *) buff1;
	struct iphdr *iph = (struct iphdr *) (buff1 + sizeof(struct ether_header));
	struct udphdr *udph = (struct udphdr *) (buff1 + sizeof(struct iphdr) + sizeof(struct ether_header));
   struct boothdr *booth = (struct boothdr *) (buff1 + sizeof(struct udphdr) + sizeof(struct iphdr) + sizeof(struct ether_header));
	FILE *fp;
   int dhcp_status = DHCP_DISCOVER;
   if((sockd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
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
      recv(sockd,(char *) &buff1, sizeof(buff1), 0x0);
      switch (dhcp_status)
      {
         case DHCP_DISCOVER:
            if(iph->protocol == 17 && udph->source == htons(68) && udph->dest == htons(67)){
               printf("DHCP_DISCOVER\n");
               // impress�o do conteudo - exemplo Endereco Destino e Endereco Origem   
               //printf("MAC Destino: %x:%x:%x:%x:%x:%x \n", buff1[0],buff1[1],buff1[2],buff1[3],buff1[4],buff1[5]);
               //printf("MAC Origem:  %x:%x:%x:%x:%x:%x \n", buff1[6],buff1[7],buff1[8],buff1[9],buff1[10],buff1[11]);
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
               printf("--------------------------------------------------\n");
               dhcp_status = DHCP_REQUEST;

            }
         break;

         case DHCP_REQUEST:
           printf("DHCP_REQUEST\n");
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