#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <winsock2.h>
#define BUF_SIZE 256

struct ether_header
{
	u_int8_t ether_dhost[6];
	u_int8_t ether_shost[6];
	u_int16_t ether_type;
};

struct ip_header{
    u_char  ip_vhl;
    u_char  ip_tos;
    u_short ip_len;
    u_short ip_id;
    u_short ip_off;
    u_char  ip_ttl;
    u_char  ip_p;
    u_short ip_sum;
    struct in_addr ip_src;
    struct in_addr ip_dst;
};

char *networkCard(void);
static void gotPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *content);

int main()
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	char *networkCardID = networkCard();
	if(!networkCardID) {
		fprintf(stderr, "Could not get network card ID\n");
		exit(1);
	}

	handle = pcap_open_live(networkCardID, 65535, 0, 1, errbuf);
	if(!handle) {
		fprintf(stderr, "%s\n", errbuf);
		exit(1);
	}

	pcap_loop(handle, -1, gotPacket, NULL);

	return 0;
}

char *networkCard(void)
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int inum;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i = 0;
    static output[BUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    //output network adapter
    for(d=alldevs; d; d=d->next) {
        printf("%d. %s\n", ++i, d->name);
        if (d->description) {
            printf("\t(%s)\n", d->description);
        }
        else {
            printf("\t(No description available)\n");
        }

        //output addresses
        pcap_addr_t *a;
        for(a=d->addresses;a;a=a->next) {
            if(a->addr->sa_family == AF_INET){
                if (a->addr) {
                    printf("\tAddress: %s\n", inet_ntoa(((struct sockaddr_in *)(a->addr))->sin_addr));
                }
                if (a->broadaddr) {
                    printf("\tBroadcast Address: %s\n", inet_ntoa(((struct sockaddr_in *)(a->broadaddr))->sin_addr));
                }
                if (a->netmask) {
                    printf("\tNetmask Address: %s\n", inet_ntoa(((struct sockaddr_in *)(a->netmask))->sin_addr));
                }
            }
        }
    }

    if(i==0) {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        exit(1);
    }

    printf("Enter the interface number (1-%d): ",i);
    scanf("%d%*c", &inum);

    if(inum < 1 || inum > i) {
        printf("\nInterface number out of range.\n");
        pcap_freealldevs(alldevs);
        exit(1);
    }

    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
    snprintf(output, sizeof(output), "%s", d->name);

    pcap_freealldevs(alldevs);

    return output;
}

static void gotPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *content)
{
	static int count = 0;
	struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec;
    struct ether_header *ether;
	struct ip_header *ip;

	//timestamp to string
    local_tv_sec = header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

	//show timestamp and capture length
	printf("Capture No. %d packet at %s.%.6d length: %4u\n", count++, timestr, header->ts.tv_usec, header->caplen);

	ether = (struct ether_header *)content;
	if(ether->ether_type == ntohs(0x0800)) {//ip
		printf("It is a IP packet\n");
		ip = (struct ip_header *)(content + 14);
		printf("Src IP Address: %12s ==> ", inet_ntoa(ip->ip_src));
		printf("Dst IP Address: %12s\n", inet_ntoa(ip->ip_dst));
		printf("The next protocol is ");
		switch(ip->ip_p) {
		case IPPROTO_TCP: printf("TCP\n"); break;
		case IPPROTO_UDP: printf("UDP\n"); break;
		case IPPROTO_ICMP: printf("ICMP\n"); break;
		default: printf("Unknown\n"); break;
		}
	}
	else if(ether->ether_type == ntohs(0x0806)) { //arp
		printf("It is an ARP packet\n");
	}
	else {
		printf("Other packet\n");
	}
	printf("\n");
	fflush(stdout);
}
