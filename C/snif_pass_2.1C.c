#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <ctype.h>
#include <string.h>

/* Ethernet header */
struct ethheader
{
  u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type;                 /* IP? ARP? RARP? etc */
};

/* IP Header */
struct ipheader
{
  unsigned char iph_ihl : 4,       //IP header length
      iph_ver : 4;                 //IP version
  unsigned char iph_tos;           //Type of service
  unsigned short int iph_len;      //IP Packet length (data + header)
  unsigned short int iph_ident;    //Identification
  unsigned short int iph_flag : 3, //Fragmentation flags
      iph_offset : 13;             //Flags offset
  unsigned char iph_ttl;           //Time to Live
  unsigned char iph_protocol;      //Protocol type
  unsigned short int iph_chksum;   //IP datagram checksum
  struct in_addr iph_sourceip;     //Source IP address
  struct in_addr iph_destip;       //Destination IP address
  unsigned char icmp_type;
  unsigned char icmp_code;
};

/* TCP header */
typedef unsigned int tcp_seq;
struct tcpheader
{
  unsigned short th_sport; /* source port */
  unsigned short th_dport; /* destination port */
  tcp_seq th_seq;          /* sequence number */
  tcp_seq th_ack;          /* acknowledgement number */
  unsigned th_offx2;       /* data offset, rsvd */
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
  unsigned char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
  unsigned short th_win; /* window */
  unsigned short th_sum; /* checksum */
  unsigned short th_urp; /* urgent pointer */
};

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800)
  { // 0x0800 is IP type
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

    /* determine protocol */

    struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader));

    // print the password
    char *data = (u_char *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader) + sizeof(struct tcpheader));
    int size_data = ntohs(ip->iph_len) - (sizeof(struct ipheader) + sizeof(struct tcpheader));
    {
      printf("   From: %s\n", inet_ntoa(ip->iph_sourceip));
      printf("   To: %s\n", inet_ntoa(ip->iph_destip));
      printf("      password latter = :");
      for (size_t i = 0; i < strlen(data); i++)
      {
        if (isprint(*(data + i)))
        {
          printf("%c", *(data + i));
        }
        else
        {
          printf(".");
        }
      }
      printf("\n\n");
    }
  }
  return;
}


int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_tcp[] = "tcp"; // filter TCP
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC
  handle = pcap_open_live("lo", BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL)
  {
    printf("cant open live pcap session, error: %s\n", errbuf);
    return 1;
  }
  printf("pcap open live is done successfully!\n");
  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_tcp, 0, net);
  pcap_setfilter(handle, &fp);
  printf("start sniffing..\n");

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);
  printf("close socket!\n");

  pcap_close(handle); //Close the handle
  return 0;
}