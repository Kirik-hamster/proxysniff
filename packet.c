#include <stdio.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "packet.h"

// IntelliSense: отключаем ложные ошибки на tcphdr и TH_*
#ifdef __INTELLISENSE__
#pragma diag_suppress 833
#pragma diag_suppress 20
#endif

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
    inet_ntop(AF_INET, &(ip->saddr), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->daddr), dst_ip, INET_ADDRSTRLEN);
    printf("IP: %s -> %s, TTL: %d, Protocol: %d",
           src_ip, dst_ip, ip->ttl, ip->protocol);
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

// Определяет тип пакета и вызывает соответствующие разборщики
void process_packet(const unsigned char *buffer, uint16_t etype) {
    parse_ethernet(buffer);

    if (etype == ETHERTYPE_IP) {
        struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ether_header));
        parse_ip((unsigned char *)iph);

        int ip_header_len = iph->ihl * 4;
        if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
            parse_tcp_udp((unsigned char *)(buffer + sizeof(struct ether_header) + ip_header_len),
                          iph->protocol);
        }
    } else if (etype == ETHERTYPE_ARP) {
        printf("ARP packet\n");
    } else if (etype == ETHERTYPE_IPV6) {
        printf("IPv6 packet (parsing not implemented)\n");
    } else {
        printf("Unknown type\n");
    }
    printf("----------------------------------------\n");
}