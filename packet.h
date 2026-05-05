#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>

/**
 * process_packet — разбирает пакет и выводит его содержимое.
 * Теперь принимает полный размер packet_size для корректного вычисления полезной нагрузки.
 */
void process_packet(const unsigned char *buffer, int packet_size);

#endif