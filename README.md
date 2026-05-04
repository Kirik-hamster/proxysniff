# proxysniff

Network sniffer and proxy utility — учебный проект на C.

## Возможности

- Захват Ethernet-фреймов через raw socket (AF_PACKET)
- Разбор заголовков Ethernet, IPv4, TCP/UDP
- Чтение имени сетевого интерфейса из `.env`
- Корректное завершение по Ctrl+C (обработка SIGINT)

## Требования

- Linux (протестировано на Ubuntu)
- Права root (нужны для raw socket)
- gcc, make (build-essential)

Имя интерфейса можно узнать командой `ip link`.

## Сборка и запуск

```bash
gcc -o proxysniff main.c packet.c
sudo ./proxysniff
```