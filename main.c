#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include "packet.h"

int main() {
    int sock, ret, len;
    char buffer[65535];
    struct sockaddr_in from;
    struct in_addr src, dst;
    struct ifreq ifr;
    char *interface = "en0"; //네트워크 카드 설정
    struct ip_header_t *ip = (struct ip_header_t *)&buffer;
    struct tcp_header_t *tcp;
    struct udp_header_t *udp;
    struct icmp_header_t *icmp;
    char *data; // 데이터 필드 시작을 가리킬 포인터

    sock = socket(PF_INET, SOCK_RAW, IPPROTO_IP); // RAW 소켓 생성
    if (sock < 0) {
        perror("Socket creation failed"); // 소켓 생성 실패 시 오류 출력
        return -1;
    }

    strncpy(ifr.ifr_name, interface, strlen(interface)+1);

    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) { // 인터페이스 플래그 가져오기
        perror("SIOCGIFFLAGS error : "); // 실패 시 오류 메시지 출력
        exit(1);
    }

    ifr.ifr_flags |= IFF_PROMISC;  // 프로미스큐어스 모드 설정

    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
        perror("Could not set the PROMISC flag : "); // 실패 시 오류 메시지 출력
        exit(1);
    }

    len = sizeof(from);  // 주소 구조체의 크기

    while(1) {
        memset(buffer, 0x00, sizeof(buffer)); // 버퍼 초기화
        ret = recvfrom(sock, buffer, sizeof(buffer), MSG_DONTWAIT, (struct sockaddr *)&from, &len); // 패킷 수신

        if (ret <= 0) continue;  // 데이터가 없거나 오류 시 다음 반복으로

        printf("Received data = %d bytes\n", ret); // 수신된 데이터 크기 출력
        src.s_addr = ip->src_ip; // 소스 IP 주소 설정
        dst.s_addr = ip->dst_ip; // 목적지 IP 주소 설정
        printf("================ IP header ===============\n");
        printf("Src IP = %s\n", inet_ntoa(src)); // 소스 IP 주소 출력
        printf("Dst IP = %s\n", inet_ntoa(dst)); // 목적지 IP 주소 출력
        printf("Total length = %d\n", ntohs(ip->length)); // 전체 길이 출력
        printf("Identification = %d\n", ntohs(ip->id)); // 식별자 출력
        printf("TTL = %d\n", ip->ttl);  // Time To Leave 출력
        printf("Protocol = %d\n", ip->protocol); // 프로토콜 번호 출력
        printf("Checksum = 0x%X\n", ntohs(ip->checksum)); // 체크섬 출력

        switch (ip->protocol) {  // 프로토콜별 switch case문
            case PROTO_TCP:
                tcp = (struct tcp_header_t *)(buffer + (4 * ip->hlen)); // TCP 헤더 위치 설정
                data = (char *)(buffer + (4 * ip->hlen) + (4 * tcp->hlen));  // 데이터 위치 설정
                printf("=============== TCP header ==============\n");
                printf("Src port = %d\n", ntohs(tcp->src_port));  // 소스 포트 출력
                printf("Dst port = %d\n", ntohs(tcp->dst_port));  // 목적지 포트 출력
                printf("Sequence number = 0x%X\n", ntohl(tcp->seqnum)); // 시퀀스 번호 출력
                printf("Acknowledgment number = 0x%X\n", ntohl(tcp->acknum)); // 확인 번호 출력
                printf("Checksum = 0x%X\n", ntohs(tcp->checksum)); // 체크섬 출력
                break;
            case PROTO_UDP:
                udp = (struct udp_header_t *)(buffer + (4 * ip->hlen));   // UDP 헤더 위치 설정
                data = (char *)(buffer + (4 * ip->hlen) + 8); // 데이터 위치 설정
                printf("=============== UDP header ==============\n");
                printf("Src port = %d\n", ntohs(udp->src_port)); // 소스 포트 출력
                printf("Dst port = %d\n", ntohs(udp->dst_port)); // 목적지 포트 출력
                printf("Length = %d\n", ntohs(udp->length)); // 길이 출력
                printf("Checksum = 0x%X\n", ntohs(udp->checksum)); // 체크섬 출력
                break;
            case PROTO_ICMP:
                icmp = (struct icmp_header_t *)(buffer + (4 * ip->hlen)); // ICMP 헤더 위치 설정
                data = (char *)(buffer + (4 * ip->hlen) + 8); // 데이터 위치 설정
                printf("=============== ICMP header ==============\n");
                printf("Type = %d\n", icmp->type); // 타입 출력
                printf("Code = %d\n", icmp->code);  // 코드 출력
                printf("Checksum = 0x%X\n", ntohs(icmp->checksum)); // 체크섬 출력
                printf("ID = %d\n", ntohs(icmp->id)); // ID 출력
                printf("Seq = %d\n", ntohs(icmp->seq)); // 시퀀스 번호 출력
                break;
            default:
                data = (char *)(buffer + (4 * ip->hlen)); // 추가 헤더 없을 때 데이터 위치 설정
                printf("No additional protocol information available.\n");
                break;
        }

        printf("=============== DATA field ==============\n");
        while (*data && isprint(*data) || isspace(*data)) {
            printf("%c", *data++);
        }
        printf("\n\n\n\n\n");
    }

    return 0;
}
