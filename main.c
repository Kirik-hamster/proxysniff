#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include "packet.h"

#define VERSION "0.1.0"

volatile sig_atomic_t running = 1;

void sigint_handler(int sig) {
    (void)sig;
    running = 0;
}

void print_help(const char *progname) {
    printf("Usage: %s [OPTIONS]\n", progname);
    printf("Network sniffer and proxy utility (educational project)\n\n");
    printf("Options:\n");
    printf("  --help        Show this help message\n");
    printf("  --version     Show version\n");
    printf("  --sniff       Start packet sniffer (default if no arguments)\n");
}

void select_interface(char *iface, size_t size) {
    struct ifaddrs *addrs, *tmp;
    getifaddrs(&addrs);
    tmp = addrs;

    int i = 0;
    printf("Available interfaces:\n");
    while (tmp) {
        if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_PACKET) {
            printf("[%d] %s\n", i++, tmp->ifa_name);
        }
        tmp = tmp->ifa_next;
    }

    int choice;
    printf("Select interface index: ");
    scanf("%d", &choice);

    // Снова проходим по списку, чтобы найти выбранный индекс
    tmp = addrs;
    int curr = 0;
    while (tmp) {
        if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_PACKET) {
            if (curr == choice) {
                strncpy(iface, tmp->ifa_name, size - 1);
                break;
            }
            curr++;
        }
        tmp = tmp->ifa_next;
    }
    freeifaddrs(addrs);
}

int main(int argc, char *argv[]) {
    // Если передан аргумент --help
    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        print_help(argv[0]);
        return 0;
    }

    // Если передан аргумент --version
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        printf("proxysniff version %s\n", VERSION);
        return 0;
    }

    // Выбор интерфейса
    char iface[32];
    select_interface(iface, sizeof(iface));

    printf("proxysniff %s - Starting sniffer on %s...\n", VERSION, iface);

    int raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_sock == -1) {
        perror("socket() failed");
        return 1;
    }
    printf("[+] Raw socket created\n");

    unsigned int ifindex = if_nametoindex(iface);
    if (ifindex == 0) {
        fprintf(stderr, "Interface %s not found. Use 'ip link' to check.\n", iface);
        close(raw_sock);
        return 1;
    }

    struct packet_mreq mreq;
    mreq.mr_ifindex = ifindex;
    mreq.mr_type = PACKET_MR_PROMISC;
    if (setsockopt(raw_sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == -1) {
        perror("setsockopt promisc failed");
    } else {
        printf("[+] Interface %s set to promiscuous mode\n", iface);
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    if (bind(raw_sock, (struct sockaddr *)&sll, sizeof(sll)) == -1) {
        perror("bind failed");
        close(raw_sock);
        return 1;
    }
    printf("[+] Bound to interface %s\n", iface);

    signal(SIGINT, sigint_handler);

    printf("[*] Listening on %s... (Ctrl+C to stop)\n\n", iface);
    while (running) {
        unsigned char buffer[65536];
        struct sockaddr_ll src_addr;
        socklen_t addr_len = sizeof(src_addr);
        ssize_t packet_size = recvfrom(raw_sock, buffer, sizeof(buffer), 0,
                                       (struct sockaddr *)&src_addr, &addr_len);
        if (packet_size == -1) {
            perror("recvfrom failed");
            break;
        }

        struct ether_header *eth = (struct ether_header *)buffer;
        uint16_t etype = ntohs(eth->ether_type);
        process_packet(buffer, etype); 
    }

    close(raw_sock);
    printf("[+] Socket closed. Sniffer done.\n");
    return 0;
}