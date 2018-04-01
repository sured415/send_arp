#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in_systm.h>
#include <libnet/libnet-macros.h>
#include <libnet/libnet-headers.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/in_systm.h>
#include <libnet/libnet-macros.h>
#include <libnet/libnet-headers.h>

struct libnet_ethernet_hdr ehtH;
struct libnet_arp_hdr arpH;
struct ifreq s;
int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
struct arpAddr {
	u_int8_t sha[6];
	u_int8_t spa[4];
	u_int8_t tha[6];
	u_int8_t tpa[4];
} req;

int getAttackerMac() {
	strcpy(s.ifr_name, "eth0");
	if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
//	printf("Get Attacker Mac = ");
//	for (int i = 0; i < 6; ++i) printf("%02x", (unsigned char) s.ifr_hwaddr.sa_data[i]);
  	puts("\n");
  	return 0;
  	}
  	return 1;
}

int getAttackerIP() {
	char ipstr[40];
	strcpy(s.ifr_name, "eth0");
	ioctl(fd, SIOCGIFADDR, &s);
	memcpy(req.spa, (void*)&(((struct sockaddr_in *)&s.ifr_addr)->sin_addr), sizeof(((struct sockaddr_in *)&s.ifr_addr)->sin_addr));

	return 0;
}

int makereq() {
	for(int i=0; i<6; i++) {
		ehtH.ether_dhost[i] = 255;
		ehtH.ether_shost[i] = (unsigned char) s.ifr_hwaddr.sa_data[i];
		req.sha[i] = ehtH.ether_shost[i];
		req.tha[i] = 0;
	}

	ehtH.ether_type = ntohs(ETHERTYPE_ARP);
	arpH.ar_hrd = ARPHRD_ETHER;
	arpH.ar_pro = ntohs(ETHERTYPE_IP);
	arpH.ar_hln = 6;
	arpH.ar_pln = 4;
	arpH.ar_op = ntohs(ARPOP_REQUEST);
	return 0;
}

int main(int argc, char* argv[]) {

	/*if (argc != 3) {
		return -1;
	}*/

	getAttackerIP();
	getAttackerMac();

	makereq();
	char buf[20];
	inet_pton(AF_INET, argv[1], req.tpa);


	printf("(si) Attacker Mac = ");
        for (int i = 0; i < 6; ++i) printf("%02x ", req.sha[i]);
	printf("\n");
	printf("(si) Attacker ip = %02x %02x %02x %02x\n", req.spa[0],req.spa[1],req.spa[2],req.spa[3]);
	printf("(tm) Target Mac = ");
        for (int i = 0; i < 6; ++i) printf("%02x ", req.tha[i]);
	printf("\n");
	printf("(ti) Target ip = %02x %02x %02x %02x\n", req.tpa[0],req.tpa[1],req.tpa[2],req.tpa[3]);

	return 0;
}
