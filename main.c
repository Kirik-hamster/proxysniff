#include <stdio.h>
#include <string.h>

#define VERSION "0.1.0"

void print_help(const char *progname) {
    printf("Usage: %s [OPTIONS]\n", progname);
    printf("Network sniffer and proxy utility (educational project)\n\n");
    printf("Options:\n");
    printf("  --help        Show this help message\n");
    printf("  --version     Show version\n");
    printf("  --sniff       Start packet sniffer (default if no arguments)\n");
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

    // Основной режим (по умолчанию или --sniff)
    printf("proxysniff %s - Network sniffer mode\n", VERSION);
    printf("Initializing raw socket... (not yet implemented)\n");
    printf("Listening on interface eth0...\n");
    printf("Waiting for packets... (Ctrl+C to stop)\n\n");

    // Здесь в будущем будет бесконечный цикл захвата пакетов
    // while (1) { ... }

    return 0;
}