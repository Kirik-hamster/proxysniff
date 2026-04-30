# proxysniff

Network sniffer and proxy utility — учебный проект на C.

## Возможности

- Захват Ethernet-фреймов через raw socket (AF_PACKET)
- Вывод размера пакета и первых байт в hex
- Поддержка Ctrl+C для корректного завершения

## Требования

- Linux (протестировано на Ubuntu)
- Права root (нужны для raw socket)
- gcc, make (build-essential)

## Сборка и запуск

```bash
gcc -o proxysniff main.c
sudo ./proxysniff
```

Для указания сетевого интерфейса измените переменную iface в main.c