#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6];    /* destination host address */
    u_char  ether_shost[6];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
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
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;               /* source port */
    u_short tcp_dport;               /* destination port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet; // Ethernet 헤더 파싱

    if (ntohs(eth->ether_type) == 0x0800) { // IP 패킷 확인
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader)); // IP 헤더 파싱

        if (ip->iph_protocol == IPPROTO_TCP) { // TCP 패킷 확인
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader)); // TCP 헤더 파싱

            // 이더넷 헤더에서 src Mac과 des Mac 추출 후 출력
            printf("Ethernet Header:\n");
            printf("    Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
                   eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
            printf("    Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
                   eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

            // IP 헤더에서 src IP와 des IP 추출 후 출력
            printf("IP Header:\n");
            printf("    Source IP: %s\n", inet_ntoa(ip->iph_sourceip)); // 송신자 IP 주소 출력
            printf("    Destination IP: %s\n", inet_ntoa(ip->iph_destip)); // 수신자 IP 주소 출력

            // TCP 헤더에서 src port와 des port 추출 후 출력
            printf("TCP Header:\n");
            printf("    Source Port: %u\n", ntohs(tcp->tcp_sport)); // 송신 포트 출력
            printf("    Destination Port: %u\n", ntohs(tcp->tcp_dport)); // 수신 포트 출력

            printf("Message:\n");
            // 패킷 데이터 시작 위치 계산
            int data_offset = sizeof(struct ethheader) + sizeof(struct ipheader) + TH_OFF(tcp) * 4;
            int data_length = ntohs(ip->iph_len) - (sizeof(struct ipheader) + TH_OFF(tcp) * 4);

            // 메시지가 있다면 출력
            if (data_length > 0) {
                printf("    ");
                for (int i = 0; i < data_length; i++) {
                    printf("%c", packet[data_offset + i]);
                }
                printf("\n");
            }
            printf("\n");
        }
    }
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp"; // TCP 패킷 필터
    bpf_u_int32 net;

    // PCAP session open
    handle = pcap_open_live("enp0s1", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        return 0;
    }

    // TCP 패킷만 받도록 필터 설정
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error:");
        return 0;
    }

    // 패킷 캡처 및 처리
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle); // 핸들 닫기
    return 0;
}
