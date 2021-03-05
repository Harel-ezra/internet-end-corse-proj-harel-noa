#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>

#include <unistd.h>
#include <string.h>
#include <netinet/ip.h>
#include <stdlib.h>

#include "myheader.h"

unsigned short in_cksum (unsigned short *buf, int length);
void send_raw_ip_packet(struct ipheader* ip);

/******************************************************************
  Spoof an ICMP echo request using an arbitrary source IP Address
*******************************************************************/
int spoof_icmp(char* src_add, char* dst_add) {
   char buffer[1500];

   memset(buffer, 0, 1500);

   /*********************************************************
      Step 1: Fill in the ICMP header.
    ********************************************************/
   struct icmpheader *icmp = (struct icmpheader *)
                             (buffer + sizeof(struct ipheader));
   icmp->icmp_type = 8; //ICMP Type: 8 is request, 0 is reply.

   // Calculate the checksum for integrity
   icmp->icmp_chksum = 0;
   icmp->icmp_chksum = in_cksum((unsigned short *)icmp,
                                 sizeof(struct icmpheader));

   /*********************************************************
      Step 2: Fill in the IP header.
    ********************************************************/
   struct ipheader *ip = (struct ipheader *) buffer;
   ip->iph_ver = 4;
   ip->iph_ihl = 5;
   ip->iph_ttl = 20;
   ip->iph_sourceip.s_addr = inet_addr(src_add);
   ip->iph_destip.s_addr = inet_addr(dst_add);
   ip->iph_protocol = IPPROTO_ICMP;
   ip->iph_len = htons(sizeof(struct ipheader) +
                       sizeof(struct icmpheader));

   /*********************************************************
      Step 3: Finally, send the spoofed packet
    ********************************************************/
   send_raw_ip_packet (ip);
      return 0;

}
   /*************************************************************
  Given an IP packet, send it out using a raw socket.
**************************************************************/
void send_raw_ip_packet(struct ipheader* ip)
{
    struct sockaddr_in dest_info;
    int enable = 1;

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sock==-1)
    {
      printf("open socket is failed\n");
      exit(-1);
    }
    printf("socket is created successfully\n");

    // Step 2: Set socket option.
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL,
                     &enable, sizeof(enable));

    // Step 3: Provide needed information about destination.
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;
    printf("start sending packet..\n");
    sleep(2);
    // Step 4: Send the packet out.
    sendto(sock, ip, ntohs(ip->iph_len), 0,
           (struct sockaddr *)&dest_info, sizeof(dest_info));
    printf("sent packet is done successfully\n");

    close(sock);
    printf("close the socket\n");

}
unsigned short in_cksum (unsigned short *buf, int length)
{
   unsigned short *w = buf;
   int nleft = length;
   int sum = 0;
   unsigned short temp=0;

   /*
    * The algorithm uses a 32 bit accumulator (sum), adds
    * sequential 16 bit words to it, and at the end, folds back all
    * the carry bits from the top 16 bits into the lower 16 bits.
    */
   while (nleft > 1)  {
       sum += *w++;
       nleft -= 2;
   }

   /* treat the odd byte at the end, if any */
   if (nleft == 1) {
        *(u_char *)(&temp) = *(u_char *)w ;
        sum += temp;
   }

   /* add back carry outs from top 16 bits to low 16 bits */
   sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16
   sum += (sum >> 16);                  // add carry
   return (unsigned short)(~sum);
}

/****************************************************************
  TCP checksum is calculated on the pseudo header, which includes
  the TCP header and data, plus some part of the IP header.
  Therefore, we need to construct the pseudo header first.
*****************************************************************/


unsigned short calculate_tcp_checksum(struct ipheader *ip)
{
   struct tcpheader *tcp = (struct tcpheader *)((u_char *)ip +
                            sizeof(struct ipheader));

   int tcp_len = ntohs(ip->iph_len) - sizeof(struct ipheader);

   /* pseudo tcp header for the checksum computation */
   struct pseudo_tcp p_tcp;
   memset(&p_tcp, 0x0, sizeof(struct pseudo_tcp));

   p_tcp.saddr  = ip->iph_sourceip.s_addr;
   p_tcp.daddr  = ip->iph_destip.s_addr;
   p_tcp.mbz    = 0;
   p_tcp.ptcl   = IPPROTO_TCP;
   p_tcp.tcpl   = htons(tcp_len);
   memcpy(&p_tcp.tcp, tcp, tcp_len);

   return  (unsigned short) in_cksum((unsigned short *)&p_tcp,
                                     tcp_len + 12);
}

/* Ethernet header */
// struct ethheader {
//   u_char  ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
//   u_char  ether_shost[ETHER_ADDR_LEN]; /* source host address */
//   u_short ether_type;                  /* IP? ARP? RARP? etc */
// };

// /* IP Header */
// struct ipheader {
//   unsigned char      iph_ihl:4, //IP header length
//                      iph_ver:4; //IP version
//   unsigned char      iph_tos; //Type of service
//   unsigned short int iph_len; //IP Packet length (data + header)
//   unsigned short int iph_ident; //Identification
//   unsigned short int iph_flag:3, //Fragmentation flags
//                      iph_offset:13; //Flags offset
//   unsigned char      iph_ttl; //Time to Live
//   unsigned char      iph_protocol; //Protocol type
//   unsigned short int iph_chksum; //IP datagram checksum
//   struct  in_addr    iph_sourceip; //Source IP address 
//   struct  in_addr    iph_destip;   //Destination IP address 
//   unsigned char icmp_type;
//   unsigned char icmp_code;
// };

void got_packet(u_char *args, const struct pcap_pkthdr *header, 
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 

    /* determine protocol */
      printf("   From: %s\n", inet_ntoa(ip->iph_sourceip));  
      printf("   To: %s\n", inet_ntoa(ip->iph_destip)); 
      spoof_icmp(inet_ntoa(ip->iph_sourceip),inet_ntoa(ip->iph_destip) );
      printf("\n");           
      return;
    }
  }

 
/**********************************************
 * Listing 12.3: Packet Capturing using raw libpcap
 **********************************************/
int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_icmp[] = "icmp"; // filter ICMP pkt
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf); 
  if(handle==NULL)
  {
    printf("cant open live pcap session, error: %s\n", errbuf);
    return 1;
  }
  printf("pcap open live is done successfully!\n");
  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_icmp, 0, net);
  pcap_setfilter(handle, &fp);                             
  printf("start sniffing..\n");

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);                
  printf("close socket!\n");

  pcap_close(handle);   //Close the handle 
  return 0;
} 