#include <stdio.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "packet.h"

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
    struct ip *ip = (struct ip *)buffer;
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->ip_dst), dst_ip, INET_ADDRSTRLEN);
    printf("IP: %s -> %s, TTL: %d, Protocol: %d", src_ip, dst_ip, ip->ip_ttl, ip->ip_p);
    if (ip->ip_p == IPPROTO_TCP) printf(" (TCP)");
    else if (ip->ip_p == IPPROTO_UDP) printf(" (UDP)");
    else if (ip->ip_p == IPPROTO_ICMP) printf(" (ICMP)");
    printf("\n");
}

// Вывести порты TCP/UDP и флаги (SYN/ACK/FIN).
static void parse_tcp_udp(const unsigned char *buffer, int protocol) {
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)buffer;
        printf("TCP ports: %d -> %d", ntohs(tcp->source), ntohs(tcp->dest));
        if (tcp->syn) printf(" [SYN]");
        if (tcp->ack) printf(" [ACK]");
        if (tcp->fin) printf(" [FIN]");
        printf("\n");
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)buffer;
        printf("UDP ports: %d -> %d\n", ntohs(udp->source), ntohs(udp->dest));
    }
}

// Определяет тип пакета и вызывает соответствующие внутренние разборщики.
void process_packet(const unsigned char *buffer, uint16_t etype) {
    parse_ethernet(buffer);

    if (etype == ETHERTYPE_IP) {
        struct ip *ip = (struct ip *)(buffer + sizeof(struct ether_header));
        parse_ip((unsigned char *)ip);

        int ip_header_len = ip->ip_hl * 4;
        if (ip->ip_p == IPPROTO_TCP || ip->ip_p == IPPROTO_UDP) {
            parse_tcp_udp((unsigned char *)(buffer + sizeof(struct ether_header) + ip_header_len), ip->ip_p);
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