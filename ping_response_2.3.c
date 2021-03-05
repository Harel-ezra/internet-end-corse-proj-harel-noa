#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h> // gettimeofday
#include <ctype.h>

// ICMP header len for echo req
#define ICMP_HDRLEN 8 

// Checksum algo
unsigned short calculate_checksum(unsigned short * paddress, int len);

#define SOURCE_IP "10.0.2.15"
// i.e the gateway or ping to google.com for their ip-address
#define DESTINATION_IP "10.0.2.4"

int send_icmp ()
{
    struct icmp icmphdr; // ICMP-header
    char data[IP_MAXPACKET] = "This is the ping.\n";
    int datalen = strlen(data) + 1;

    //===================
    // ICMP header
    //===================

    // Message Type (8 bits): ICMP_ECHO_REQUEST
    icmphdr.icmp_type = ICMP_ECHO;

    // Message Code (8 bits): echo request
    icmphdr.icmp_code = 0;

    // Identifier (16 bits): some number to trace the response.
    // It will be copied to the response packet and used to map response to the request sent earlier.
    // Thus, it serves as a Transaction-ID when we need to make "ping"
    icmphdr.icmp_id = 18; // hai

    // Sequence Number (16 bits): starts at 0
    icmphdr.icmp_seq = 0;

    // ICMP header checksum (16 bits): set to 0 not to include into checksum calculation
    icmphdr.icmp_cksum = 0;

    // Combine the packet 
    char packet[IP_MAXPACKET];

    // Next, ICMP header
    memcpy ((packet), &icmphdr, ICMP_HDRLEN);

    // After ICMP header, add the ICMP data.
    memcpy (packet+ ICMP_HDRLEN, data, datalen);

    // Calculate the ICMP header checksum
    icmphdr.icmp_cksum = calculate_checksum((unsigned short *) (packet ), ICMP_HDRLEN + datalen);
    memcpy ((packet ), &icmphdr, ICMP_HDRLEN);

    struct sockaddr_in dest_in;
    memset (&dest_in, 0, sizeof (struct sockaddr_in));
    dest_in.sin_family = AF_INET;
    dest_in.sin_addr.s_addr = inet_addr(DESTINATION_IP);

    // Create raw socket for IP-RAW (make IP-header by yourself)
    int sock = -1;
    if ((sock = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) 
    {
        fprintf (stderr, "socket() failed with error: %d", errno);
        fprintf (stderr, "To create a raw socket, the process needs to be run by Admin/root user.\n\n");
        return -1;
    }

printf("socket is created successfully\n");

struct timeval start, end;

printf("start sending the ping message..\n");
sleep(2);
//gettimeofday(&start, NULL);
    // Send the packet using sendto() for sending datagrams.
    if (sendto (sock, packet, ICMP_HDRLEN + datalen, 0, (struct sockaddr *) &dest_in, sizeof (dest_in)) == -1)  
    {
        fprintf (stderr, "sendto() failed with error: %d", errno);
        return -1;
    }
    printf("sent packet is done successfully\n");
    if (recvfrom (sock, packet, ICMP_HDRLEN + datalen, 0, NULL,NULL) == -1)  
{
        fprintf (stderr, "recive() failed with error: %d" , errno);
        return -1;
    }
// gettimeofday(&end, NULL);
// float rrt=((end.tv_sec * 1000000 + end.tv_usec) - (start.tv_sec * 1000000 + start.tv_usec));
// printf("Time taken for sent ping message is : %.2f micro seconds\n",rrt);

  close(sock);
    printf("close the socket\n");

  return 0;
}

// Compute checksum (RFC 1071).
unsigned short calculate_checksum(unsigned short * paddress, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short * w = paddress;
	unsigned short answer = 0;

	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1)
	{
		*((unsigned char *)&answer) = *((unsigned char *)w);
		sum += answer;
	}

	// add back carry outs from top 16 bits to low 16 bits
	sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
	sum += (sum >> 16);                 // add carry
	answer = ~sum;                      // truncate to 16 bits

	return answer;
}
/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char  ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type;                  /* IP? ARP? RARP? etc */
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address 
  struct  in_addr    iph_destip;   //Destination IP address 
  unsigned char icmp_type;
  unsigned char icmp_code;
};

/* TCP header */
	typedef unsigned int tcp_seq;
    struct tcpheader {
            unsigned short th_sport;	/* source port */
            unsigned short th_dport;	/* destination port */
            tcp_seq th_seq;		/* sequence number */
            tcp_seq th_ack;		/* acknowledgement number */
            unsigned th_offx2;	/* data offset, rsvd */
        #define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
            unsigned char th_flags;
        #define TH_FIN 0x01
        #define TH_SYN 0x02
        #define TH_RST 0x04
        #define TH_PUSH 0x08
        #define TH_ACK 0x10
        #define TH_URG 0x20
        #define TH_ECE 0x40
        #define TH_CWR 0x80
        #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
            unsigned short th_win;		/* window */
            unsigned short th_sum;		/* checksum */
            unsigned short th_urp;		/* urgent pointer */
    };

void got_packet(u_char *args, const struct pcap_pkthdr *header, 
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 

    /* determine protocol */
    if(ip->iph_protocol==IPPROTO_ICMP) {       
      printf("   From: %s\n", inet_ntoa(ip->iph_sourceip));  
      printf("   To: %s\n", inet_ntoa(ip->iph_destip));                           
      char * data=(u_char *)packet +sizeof(struct ethheader) + sizeof( struct ipheader) + sizeof(struct tcpheader);
      int size_data=ntohs(ip->iph_len) - (sizeof(struct ipheader) + sizeof(struct tcpheader));
      int j=ntohs(ip->iph_len)- size_data;
      printf("%d", size_data);
      if(size_data>0)
      {
        while(j>0)
        {
          data++;
          j--;
        }
        printf("        data:");
        for (int i=0;i<size_data;i++)
        {
          if(isprint(*data))
          {
            printf("%c", *data);
          }
          else
          {
            printf(".");
          }
          data++;
        }
      }
      printf("\n\n");
      return;
    }
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
  char filter_exp[] = "ip proto icmp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3, my ethernet card name
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf); 
  if(handle==NULL)
  {
    printf("cant open live pcap session, error: %s\n", errbuf);
    return 1;
  }
  printf("pcap open live is done successfully!\n");
  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);      
  pcap_setfilter(handle, &fp);                             
  printf("start sniffing..\n");
  send_icmp();

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);                
  printf("close socket!\n");

  pcap_close(handle);   //Close the handle 
  return 0;
} 
