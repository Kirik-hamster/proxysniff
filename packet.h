#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>

/**
 * process_packet — разобрать и вывести информацию о захваченном пакете.
 * @buffer: указатель на начало Ethernet-фрейма (весь пакет)
 * @etype:  EtherType из Ethernet-заголовка (в хостовом порядке байт)
 */
void process_packet(const unsigned char *buffer, uint16_t etype);

#endif