import os
import subprocess
from scapy.all import ARP, Ether, srp

def get_subnet():
    """Alt ağı belirler."""
    result = subprocess.run(['ip', 'route'], stdout=subprocess.PIPE, text=True)
    lines = result.stdout.splitlines()
    for line in lines:
        if "src" in line:
            parts = line.split()
            for part in parts:
                if "/" in part:
                    return part  # Alt ağ formatında: 192.168.1.0/24
    return None

def scan_network(subnet):
    """Ağı tarar ve cihazları döndürür."""
    devices = []
    print(f"Taranan alt ağ: {subnet}")

    # ARP isteği gönder
    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=2, verbose=0)[0]

    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

def get_device_manufacturer(mac):
    """MAC adresine göre üretici bilgisi döndürür."""
    if mac.startswith("00:1A:2B"):
        return "Samsung"
    elif mac.startswith("00:1B:63"):
        return "Apple"
    elif mac.startswith("AC:DE:48"):
        return "TP-Link"
    else:
        return "Bilinmeyen Üretici"

if __name__ == "__main__":
    print("Ağ tarayıcısı başlatılıyor...")
    subnet = get_subnet()

    if subnet is None:
        print("Alt ağ bilgisi alınamadı. Ağınıza bağlı olduğunuzdan emin olun.")
        exit(1)

    devices = scan_network(subnet)

    print("\nAğdaki cihazlar:")
    print("IP Address\tMAC Address\t\tManufacturer")
    for device in devices:
        manufacturer = get_device_manufacturer(device['mac'])
        print(f"{device['ip']}\t{device['mac']}\t{manufacturer}")
