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

int getAttackerMac() {
	strcpy(s.ifr_name, "eth0");
	if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
	for (int i = 0; i < 6; ++i) printf("%02x", (unsigned char) s.ifr_addr.sa_data[i]);
  	puts("\n");
  	return 0;
  	}
  	return 1;
}

int getAttackerIP() {
	strcpy(s.ifr_name, "eth0");
	ioctl(fd, SIOCGIFADDR, &s);
 	printf("%s\n", inet_ntoa(((struct sockaddr_in *)&s.ifr_addr)->sin_addr));
	return 0;
}

int makereq() {
	for(int i=0; i<6; i++) {
		ehtH.ether_dhost[i] = 255;
		ehtH.ether_shost[i] = (unsigned char) s.ifr_addr.sa_data[i];
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




	printf("src mac : %02X:%02X:%02X:%02X:%02X:%02X\n",ehtH.ether_shost[0],ehtH.ether_shost[1],ehtH.ether_shost[2],ehtH.ether_shost[3],ehtH.ether_shost[4],ehtH.ether_shost[5]);
	printf("drc mac : %02X:%02X:%02X:%02X:%02X:%02X\n",ehtH.ether_dhost[0],ehtH.ether_dhost[1],ehtH.ether_dhost[2],ehtH.ether_dhost[3],ehtH.ether_dhost[4],ehtH.ether_dhost[5]);
	printf("ether type : %04X\n", ntohs(ehtH.ether_type));
	printf("%s\n", argv[1]);

	return 0;
}
