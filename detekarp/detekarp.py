#!/usr/bin/env python
import scapy.all as scapy

def dapetmac_nuz(ip,):
    minta_arp = scapy.ARP(pdst=ip)
    penyiaran = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    minta_arp_penyiaran = penyiaran/minta_arp
    daftar_terjawab = scapy.srp(minta_arp_penyiaran, timeout=1, verbose=False)[0]

    return daftar_terjawab[0][1].hwsrc
def intip_nuz(intface):
    scapy.sniff(iface=intface, store=False, prn=prosesintip_nuz)


def prosesintip_nuz(kardus):
    if kardus.haslayer(scapy.ARP) and kardus[scapy.ARP].op == 2:
        try:
            macasli = dapetmac_nuz(kardus[scapy.ARP].psrc)
            responmac = kardus[scapy.ARP].hwsrc

            if macasli != responmac:
                print("SERANGAN TERDETEKSI!")

        except IndexError:
            pass

intip_nuz("eth0")
penutupan = '''
    dibuat dengan niat oleh 
     ______   _ _   _ _   _ _______________
    |__  / | | | \ | | | | |__  /__  /__  /
      / /| | | |  \| | | | | / /  / /  / / 
     / /_| |_| | |\  | |_| |/ /_ / /_ / /_ 
    /____|\___/|_| \_|\___//____/____/____|

    https://steamcommunity.com/id/zunuzzz/

    =========GUNAKAN DENGAN BIJAK=========
    '''

print(penutupan)