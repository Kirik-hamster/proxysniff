#include <stdio.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <ctype.h>
#include <netdb.h>
#include "packet.h"

// IntelliSense: отключаем ложные ошибки на tcphdr и TH_*
#ifdef __INTELLISENSE__
#pragma diag_suppress 833
#pragma diag_suppress 20
#endif

static unsigned long long total_bytes = 0;

// Вспомогательная функция для превращения IP в имя
static void resolve_hostname(struct in_addr ip, char *hostname, size_t len) {
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    sa.sin_addr = ip;

    // Пытаемся получить имя. NI_NAMEREQD заставит функцию вернуть ошибку, если имени нет
    if (getnameinfo((struct sockaddr *)&sa, sizeof(sa), hostname, len, NULL, 0, NI_NAMEREQD) != 0) {
        snprintf(hostname, len, "Unknown Host");
    }
}

// Вывести MAC-адреса и тип Ethernet-фрейма.
static void parse_ethernet(const unsigned char *buffer) {
    struct ether_header *eth = (struct ether_header *)buffer;
    printf("Ethernet: ");
    printf("%02x:%02x:%02x:%02x:%02x:%02x -> ",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    uint16_t etype = ntohs(eth->ether_type);
    printf(", Type: 0x%04x", etype);
    if (etype == ETHERTYPE_IP) printf(" (IPv4)");
    else if (etype == ETHERTYPE_ARP) printf(" (ARP)");
    else if (etype == ETHERTYPE_IPV6) printf(" (IPv6)");
    printf("\n");
}

// Вывести IP-адреса, TTL и протокол из IPv4-заголовка.
static void parse_ip(const unsigned char *buffer) {
    struct iphdr *ip = (struct iphdr *)buffer;
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    char src_host[NI_MAXHOST], dst_host[NI_MAXHOST];

    inet_ntop(AF_INET, &(ip->saddr), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->daddr), dst_ip, INET_ADDRSTRLEN);

    // Резолвим имена
    resolve_hostname(*(struct in_addr *)&(ip->saddr), src_host, sizeof(src_host));
    resolve_hostname(*(struct in_addr *)&(ip->daddr), dst_host, sizeof(dst_host));

    printf("  \033[1;33mIPv4:\033[0m %s (\033[0;35m%s\033[0m) -> %s (\033[0;35m%s\033[0m)\n", 
           src_ip, src_host, dst_ip, dst_host);
    printf("        TTL: %d, Protocol: %d", ip->ttl, ip->protocol);
    if (ip->protocol == IPPROTO_TCP) printf(" (TCP)");
    else if (ip->protocol == IPPROTO_UDP) printf(" (UDP)");
    else if (ip->protocol == IPPROTO_ICMP) printf(" (ICMP)");
    printf("\n");
}

// Вывести порты TCP/UDP и флаги (SYN/ACK/FIN).
static void parse_tcp_udp(const unsigned char *buffer, int protocol) {
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)buffer;
        printf("TCP ports: %d -> %d", ntohs(tcp->th_sport), ntohs(tcp->th_dport));
        if (tcp->th_flags & TH_SYN) printf(" [SYN]");
        if (tcp->th_flags & TH_ACK) printf(" [ACK]");
        if (tcp->th_flags & TH_FIN) printf(" [FIN]");
        printf("\n");
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)buffer;
        printf("UDP ports: %d -> %d\n", ntohs(udp->uh_sport), ntohs(udp->uh_dport));
    }
}

void print_payload(const unsigned char *payload, int len) {
    for (int i = 0; i < len; i++) {
        // Делаем красивые отступы, чтобы текст не слипался в кашу
        if (i > 0 && i % 16 == 0) printf("  "); // Двойной пробел каждые 16 байт
        if (i > 0 && i % 32 == 0) printf("\n"); // Перенос строки каждые 32 байта
        
        // Главная магия:
        if (isprint(payload[i])) 
            printf("%c", payload[i]); // Если байт — это буква, цифра или знак, печатаем как есть
        else 
            printf("."); // Если это служебный байт (0x00, 0x01 и т.д.), печатаем точку
    }
    printf("\n");
}

// Определяет тип пакета и вызывает соответствующие разборщики
void process_packet(const unsigned char *buffer, int packet_size) {
    total_bytes += packet_size;
    struct ether_header *eth = (struct ether_header *)buffer;
    uint16_t etype = ntohs(eth->ether_type);

    printf("\033[1;34m[Packet Captured: %d bytes]\033[0m\n", packet_size);
    double mb = (double)total_bytes / (1024 * 1024);
    printf("\033[1;35m[Total Stats: %.4f MB | %llu bytes]\033[0m\n", mb, total_bytes);
    parse_ethernet(buffer);

    if (etype == ETHERTYPE_IP) {
        struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ether_header));
        parse_ip((unsigned char *)iph);
        int head_len = iph->ihl * 4;
        const unsigned char *payload = buffer + sizeof(struct ether_header) + head_len;
        int payload_size = packet_size - (sizeof(struct ether_header) + head_len);

        if (iph->protocol == IPPROTO_TCP) {
            parse_tcp_udp(payload, iph->protocol);
            
            int tcp_len = ((struct tcphdr *)payload)->th_off * 4;
            if (payload_size > tcp_len) {
                printf("    \033[1;30mPayload (%d bytes):\033[0m\n", payload_size - tcp_len);
                print_payload(payload + tcp_len, payload_size - tcp_len);
            }
        }
    }
    printf("------------------------------------------------------------------\n");
}