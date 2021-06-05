/*
 * Old network packet inspector I wrote long time ago
 * No library needed, only Kernel API are used
 * 
 * Strict C89 compliant
 * -Wall -Wextra -std=c89 -pedantic -Wmissing-prototypes -Wstrict-prototypes \
 * -Wold-style-definition 
 *
 * Compilation:
 * gcc -O2 -o netdump netdump.c
 *
 * Added filters, VXLAN support 
 *
 * Vincent Gerard
 */


/* Use GNU style tcphdr vs BSD style */
#define _GNU_SOURCE TRUE

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>
#include <time.h>
#include <getopt.h>

#define VXLAN_PORT 4789
#define VXLAN_HDR_SZ 8

/* GLOBAL VARIABLES ---- (used for SIGHANDLER to cleanup) */
int      ispromisc;
int      isprintall;
int      isprintmsg;
int      psock;
uint8_t *buffer;
char    *iface;


/* DATA STRUCTURES -------- */

enum { FALSE = 0, TRUE };

/* Packet vxlan status:
 * UNKNOWN    : Not yet parsed
 * NO_VLAN    : Standard packet (not on UDP 4789)
 * VXLAN_FRAME: Top level packet with VXLAN info
 * VNI_FRAME  : Virtual Network packet
 */
enum vxlan { UNKNOWN, NO_VXLAN, VXLAN_FRAME, VNI_FRAME };
typedef enum vxlan vxlan_t;


/* Record information to be printed */
struct packet {
    /* Final payload len will be recv_len - headers_len */
    vxlan_t              vxlan;
    size_t               recv_len;
    size_t               headers_len;
    uint16_t             l3_protocol; /* ETH_P_IP or ETH_P_IPV6 */
    char                 srcip[INET6_ADDRSTRLEN];
    char                 dstip[INET6_ADDRSTRLEN];
    char                 flags[4];              /* SYN|ACK|FIN|RST */
    uint16_t             source;                /* PORTS */
    uint16_t             dest;
    uint16_t             protocol;              /* IPPROT_UDP|TCP|ICMP */
    uint8_t              icmp_type;
    uint8_t              icmp_code;
    const struct packet *vxparent;
};

typedef struct packet packet_t;

struct portfilter {
/* Limit port lists to 32 ports each 
 * -t <22,80,...>
 * -u <123,4789,...>
 */
#define MAX_NUM_PORTS 32

    uint32_t filter_all;
    uint16_t num_ports;
    uint16_t port_list[MAX_NUM_PORTS];
};

typedef struct portfilter portfilter_t;

/* LOCAL FUNCTIONS ---------------------- */
void help(char *name, int retcode);
void get_signals(int afd);

int build_filter    (portfilter_t * filter, char *list);
void print_portlist (const portfilter_t * filter);
int is_port_present (uint16_t port, const struct portfilter *filter);
int allowed_port    (const packet_t * packet, const portfilter_t * filter);

int set_promisc        (int sockfd, char *iface, int type);
int get_if_mtu         (int sockfd, char *iface);
int get_if_idx         (int sockfd, char *iface);
int get_broadcast_inet (int sockfd, char *iface, struct sockaddr_in *brcast);

void print_packet        (const packet_t * packet, uint8_t * payload);

int process_vxlan_packet (const packet_t *packet,
                          const uint8_t  *vxlan_frame);

int process_ip_packet    (packet_t * packet,
                          const struct iphdr *ip,
                          const portfilter_t * tcpfilter,
                          const portfilter_t * udpfilter,
                          const struct sockaddr_in *bcastfilter);

int process_ip6_packet    (packet_t * packet,
                          const struct ip6_hdr *ip,
                          const portfilter_t * tcpfilter,
                          const portfilter_t * udpfilter,
                          int   bcast_filter);

int process_icmp_packet  (packet_t * packet,
                          const struct icmphdr * icmp);

int process_tcp_packet   (packet_t * packet,
                          const struct tcphdr * tcp,
                          const portfilter_t  * tcpfilter);

int process_udp_packet   (packet_t * packet,
                          const struct udphdr *udp,
                          const portfilter_t * udpfilter);

int listenloop   (int mtu, const portfilter_t * tcpfilter,
                  const portfilter_t * udpfilter,
                  const struct sockaddr_in *bcastfilter);

/* ------------------- START OF CODE -------------- */

int build_filter(portfilter_t * filter, char *list)
{
    const char *delim = ",";
    char       *saveptr;
    char       *token;
    int         i = 0;

    /* NONE case */
    if (strlen(list) == 4 && !strncmp("NONE", list, 4)) {
        filter->filter_all = TRUE;
        return 0;
    }
    filter->filter_all = FALSE;

    token = strtok_r(list, delim, &saveptr);

    do {
        if (i <= MAX_NUM_PORTS) {
            long int port = strtol(token, NULL, 10);
            if (port <= 0L || port > 0xFFFF) {
                fprintf(stderr,
                        "Port value should be a short integer: (\"%s\") is invalid\n",
                        token);
                return -1;
            }
            filter->port_list[i++] = (uint16_t) port;
        } else {
            fprintf(stderr,
                    "Port list is too long, maximum supported number of port is (%d)\n",
                    MAX_NUM_PORTS);
            return -1;
        }
    }
    while ((token = strtok_r(NULL, delim, &saveptr)) != NULL);
    filter->num_ports = i;
    return 0;
}

void print_portlist(const portfilter_t * filter)
{
    int i;
    if (filter->filter_all) {
        printf("NONE\n");
    } else {
        for (i = 0; i < filter->num_ports; i++)
            printf("%hu ", filter->port_list[i]);
        printf("\n");
    }
}

int is_port_present(uint16_t port, const struct portfilter *filter)
{
    int i;
    if (filter->filter_all)
        return FALSE;

    for (i = 0; i < filter->num_ports; i++)
        if (port == filter->port_list[i])
            return TRUE;
    return FALSE;
}



void help(char *name, int retcode)
{
    fprintf(stdout, "Help: %s -i <iface> [options]\n"
            "Network Packet Inspector\n\n"
            "--help\t\tshow help\n"
            "-i <interface>\tinterface to listen\n"
            "-p {0|1}\tpromiscious mode (0=0ff[DEFAULT] 1=On)\n"
            "-t <port_list>|NONE ex: -t 22,53,10,100 only show packets from/to theses TCP ports\n"
            "                        -t NONE         do not show any TCP packet\n"
            "-u <port_list>|NONE ex: (see -t semantics)\n"
            "-X\t\tPrint packet content (useful for HTTP/Clear text protocols)\n"
            "-a\t\tPrint 'exotic' IP protocols (not TCP/UDP/ICMP)\n"
            "-B\t\tignore all broadcast packets\n", name);
    exit(retcode);
}

/*______________________________________________*\
* Function set_promisc				*
* Activate/Desactivate promiscious mode		*
\*______________________________________________*/
int set_promisc(int sockfd, char *iface, int type)
{
    struct ifreq ifr;

    strncpy(ifr.ifr_name, iface, IFNAMSIZ);

    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0)
        return -1;

    if (type == TRUE) {         /* Activate */
        if (ifr.ifr_flags & IFF_PROMISC)
            ispromisc = TRUE;
        ifr.ifr_flags |= IFF_PROMISC;
    } else {                    /* Désactivate */
        ifr.ifr_flags &= ~IFF_PROMISC;
    }

    if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0)
        return -1;

    return 0;
}


/*______________________________________________*\
 *     Get MTU *
\*______________________________________________*/
int get_if_mtu(int sockfd, char *iface)
{
    struct ifreq ifr;

    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFMTU, &ifr) < 0)
        return -1;
    return ifr.ifr_mtu;
}

/*______________________________________________*\
 *     Get Kernel IF index from ifname *
\*______________________________________________*/
int get_if_idx(int sockfd, char *iface)
{
    struct ifreq ifr;

    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0)
        return -1;
    return ifr.ifr_ifindex;
}

/*______________________________________________*\
 *     Get Broadcast Addr from ifname *
\*______________________________________________*/
int get_broadcast_inet(int sockfd, char *iface, struct sockaddr_in *brcast)
{
    struct ifreq ifr;

    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFBRDADDR, &ifr) < 0)
        return 0;
    memcpy(brcast, (struct sockaddr_in *) &ifr.ifr_broadaddr,
           sizeof(struct sockaddr_in));
    return 1;
}

void print_packet(const packet_t * packet, uint8_t * payload)
{
    time_t      timer;
    char        timebuffer[26];
    struct tm  *tm_info;
    const char *proto_str;
    int         is_unknown;
    int         is_tcp;
    int         is_icmp;
    uint32_t    i;
    uint8_t     c;
    const char *flags;

    /* For VXLAN VNI packet that got there (not filtered) print top frame */
    if (packet->vxlan == VNI_FRAME)
        print_packet(packet->vxparent, NULL);

    time(&timer);
    tm_info = localtime(&timer);

    if (strftime(timebuffer, sizeof(timebuffer),
                 "%Y-%m-%d %H:%M:%S", tm_info) == 0) {
        fprintf(stderr, "strftime returned 0");
        return;
    }

    is_unknown = FALSE;
    is_tcp      = FALSE;
    is_icmp     = FALSE;

    switch (packet->protocol) {
    case (IPPROTO_UDP):
        proto_str = "UDP";
        break;
    case (IPPROTO_TCP):
        is_tcp    = TRUE;
        proto_str = "TCP";
        break;
    case (IPPROTO_ICMP):
        is_icmp    = TRUE;
        proto_str  = "ICMP";
        break;
    default:
        is_unknown = TRUE;
        proto_str  = "UNK";
        break;
    }

    if (packet->vxlan == VNI_FRAME) {
        printf("  [VXLAN SUBFRAME]    len:%5lu %4s %15s:%5hu -> %15s:%5hu ",
               packet->recv_len - packet->vxparent->headers_len, proto_str,
               packet->srcip, packet->source, packet->dstip, packet->dest);
    }
    else {
        printf("[%s] len:%5lu %4s %15s:%5hu -> %15s:%5hu ",
               timebuffer, packet->recv_len,  proto_str,
               packet->srcip, packet->source, packet->dstip, packet->dest);
    }

    if (is_unknown) {
        printf("ip protocol:%hu\n", packet->protocol);
        return;
    }
    else if (is_icmp) {
        switch (packet->icmp_type) {

        case (ICMP_ECHO):
            printf("ECHO REQUEST (PING REQ)\n");
            break;
        case (ICMP_ECHOREPLY):
            printf("ECHO REPLY   (PING REPLY)\n");
            break;
        default:        
            printf("type: %hu, code: %hu\n", packet->icmp_type,
                                             packet->icmp_code);
        }
        return;
    }
    else if (is_tcp) {
        flags = packet->flags;
        printf("FLAGS:%c%c%c%c", flags[0], flags[1], flags[2], flags[3]);
    }
    else if (packet->vxlan == VXLAN_FRAME) {
        printf("--VXLAN--\n");
        return;                 /* Content will be printed by VNI Frame */
    }

    /* Only TCP and UDP packetx get there */
    putchar('\n');

    /* Only print payload if option -X is set */
    if(!isprintmsg)
        return;

    for (i = 0; i < packet->recv_len - packet->headers_len; i++) {
        c = payload[i];
        if (!isspace(c) && c < 0x20)    /* Unprintable range */
            printf("\\x%2.2x", c);
        else
            putchar(payload[i]);
    }
    putchar('\n');

}


/* Returns TRUE if packet port is to be printed, FALSE otherwise. */
int allowed_port(const packet_t * packet, const portfilter_t * filter)
{
    /* TODO VGE: for now filter out protocol 3784 inside vxlan as too noisy */
    if (packet->vxlan == VNI_FRAME)
        return (packet->dest != 3784 && packet->source != 3784);
    else
        return (!filter ||
                is_port_present(packet->dest, filter) ||
                is_port_present(packet->source, filter));
}

int
process_icmp_packet  (packet_t * packet,
                      const struct icmphdr * icmp)
{
    packet->icmp_type = icmp->type;
    packet->icmp_code = icmp->code;

    print_packet(packet, NULL);
    return 0;
}


int
process_tcp_packet(packet_t * packet,
                   const struct tcphdr * tcp,
                   const portfilter_t  * tcpfilter)
{
    uint8_t *tcp_payload;
    int      tcp_offset;
    char    *flags;

    packet->dest   = htons(tcp->dest);
    packet->source = htons(tcp->source);

    if (!allowed_port(packet, tcpfilter))
        return FALSE;

    memset(packet->flags, ' ', sizeof(packet->flags));
    flags = packet->flags;

    if (tcp->syn)
        flags[0] = 'S';
    if (tcp->ack)
        flags[1] = 'A';
    if (tcp->fin)
        flags[2] = 'F';
    if (tcp->rst)
        flags[3] = 'R';

    tcp_offset = tcp->doff * 4;
    packet->headers_len += tcp_offset;

    tcp_payload = ((uint8_t *) tcp) + tcp_offset;

    print_packet(packet, tcp_payload);
    return 0;
}

int
process_vxlan_packet(const packet_t *packet,
                     const uint8_t  *vxlan_frame)
{
    /* Already verified that VNI_FRAME is an IP packet */
    struct iphdr  *vxip;
    packet_t       vxpacket;

    vxpacket.vxlan        = VNI_FRAME;
    vxpacket.recv_len     = packet->recv_len;
    vxpacket.headers_len  = packet->headers_len + VXLAN_HDR_SZ;
    vxpacket.vxparent     = packet;
    vxpacket.source       = 0;
    vxpacket.dest         = 0;

    vxip =
        (struct iphdr *) (vxlan_frame + VXLAN_HDR_SZ +
                          sizeof(struct ethhdr));

    /* TODO Support IPv6 Inner frame */
    /* Loop back to process_ip_packet for child packet */
    return process_ip_packet(&vxpacket, vxip, NULL, NULL, NULL);
}



int
process_udp_packet(packet_t * packet,
                   const struct udphdr *udp,
                   const portfilter_t * udpfilter)
{
    uint8_t       *payload;
    int            udp_offset;
    struct ethhdr *vxeth;

    packet->dest   = htons(udp->dest);
    packet->source = htons(udp->source);

    if (!allowed_port(packet, udpfilter))
        return FALSE;

    udp_offset = sizeof(struct udphdr);

    packet->headers_len += udp_offset;

    payload = ((uint8_t *) udp) + udp_offset;

    if (packet->vxlan == UNKNOWN) {
        if (packet->dest == VXLAN_PORT || packet->source == VXLAN_PORT) {
            packet->vxlan = VXLAN_FRAME;
        } else {
            packet->vxlan = NO_VXLAN;
        }
    }

    /* VXLAN frame printing is defered to allow filtering based on 
     * Encapsulated payload */
    if (packet->vxlan != VXLAN_FRAME)
        print_packet(packet, payload);
    else {
        /* VXFRAME packet, process if inner packet is IP */
        if (packet->recv_len - packet->headers_len <
            VXLAN_HDR_SZ + sizeof(struct ethhdr))
            return FALSE;

        vxeth = (struct ethhdr *) (payload + VXLAN_HDR_SZ);
        /* Only support IP protocol inside VXLAN */
        if (vxeth->h_proto != htons(ETH_P_IP)) {
            return FALSE;
        }
        return process_vxlan_packet(packet, payload);
    }
    return 0;
}

int
process_ip_packet(packet_t * packet,
                  const struct iphdr *ip,
                  const portfilter_t * tcpfilter,
                  const portfilter_t * udpfilter,
                  const struct sockaddr_in *bcastfilter)
{
    int       ip_offset;
    void     *ip_payload;
    uint32_t  broadcastip;

    /* If broadcast filtering is enabled, filter out broadcast packets */
    if (packet->vxlan != VNI_FRAME && bcastfilter != NULL) {
        broadcastip = bcastfilter->sin_addr.s_addr;
        /* Also filter out 255.255.255.255 IP (0xFFFFFFFF) */
        if (broadcastip == ip->saddr ||
            broadcastip == ip->daddr || 0xFFFFFFFF == ip->daddr)
            return 0;
    }

    inet_ntop(AF_INET, &ip->saddr, packet->srcip, sizeof(packet->srcip));
    inet_ntop(AF_INET, &ip->daddr, packet->dstip, sizeof(packet->dstip));
    packet->protocol = ip->protocol;

    ip_offset = ip->ihl * 4;
    ip_payload = (((uint8_t *) ip) + ip_offset);

    packet->headers_len += ip_offset;

    switch (ip->protocol) {

    case(IPPROTO_UDP):
        return process_udp_packet(packet, (const struct udphdr *) ip_payload,
                                  udpfilter);
    case(IPPROTO_TCP):
        if (packet->vxlan == UNKNOWN)
            packet->vxlan = NO_VXLAN;
        return process_tcp_packet(packet, (const struct tcphdr *) ip_payload,
                                  tcpfilter);
    case(IPPROTO_ICMP):
        return process_icmp_packet(packet,
                                   (const struct icmphdr *) ip_payload);
    default:
        if (isprintall)
            print_packet(packet, NULL); /* Unknown protocol print */
        return 0;
    }
}


int
process_ip6_packet(packet_t * packet,
                  const struct ip6_hdr *ip,
                  const portfilter_t * tcpfilter,
                  const portfilter_t * udpfilter,
                  int   bcast_filter)
{
    int       ip_offset;
    void     *ip_payload;
    struct    in6_addr broadcastip;

    inet_pton(AF_INET6, "ff02::1", &broadcastip);

    /* If broadcast filtering is enabled, filter out broadcast packets */
    if (packet->vxlan != VNI_FRAME && bcast_filter) {
        /* Also filter out 255.255.255.255 IP (0xFFFFFFFF) */
        if (!memcmp(&broadcastip,&(ip->ip6_src),sizeof(struct in6_addr)) ||
            !memcmp(&broadcastip,&(ip->ip6_dst),sizeof(struct in6_addr)))
            return 0;
    }

    inet_ntop(AF_INET6, &ip->ip6_src, packet->srcip, sizeof(packet->srcip));
    inet_ntop(AF_INET6, &ip->ip6_dst, packet->dstip, sizeof(packet->dstip));
    /* Todo, support encapsulated ipv6 headers */
    packet->protocol = ip->ip6_nxt;

    ip_offset = 40; /* Fixed IPv6 header size */
    ip_payload = (((uint8_t *) ip) + ip_offset);

    packet->headers_len += ip_offset;

    switch (packet->protocol) {

    case(IPPROTO_UDP):
        return process_udp_packet(packet, (const struct udphdr *) ip_payload,
                                  udpfilter);
    case(IPPROTO_TCP):
        if (packet->vxlan == UNKNOWN)
            packet->vxlan = NO_VXLAN;
        return process_tcp_packet(packet, (const struct tcphdr *) ip_payload,
                                  tcpfilter);
    case(IPPROTO_ICMP):
        return process_icmp_packet(packet,
                                   (const struct icmphdr *) ip_payload);
    default:
        if (isprintall)
            print_packet(packet, NULL); /* Unknown protocol print */
        return 0;
    }
}




/*
 * Signal handler to close cleanly 
 */
void get_signals(int afd)
{

    fprintf(stdout, "[-] Received signal %d ...\n", afd);
    fprintf(stdout, "[-] Network listener is shutting down ...\n");
    if (ispromisc == TRUE) {
        set_promisc(psock, iface, FALSE);
        fprintf(stdout, "[-] Promiscious flag OFF\n");
    }

    free(buffer);
    close(psock);
    exit(0);
}


/*
 * Main loop
 */
int
listenloop(int mtu, const portfilter_t * tcpfilter,
           const portfilter_t * udpfilter,
           const struct sockaddr_in *bcastfilter)
{
    packet_t       packet;
    struct iphdr    *ip;
    struct ip6_hdr  *ip6;
    struct ethhdr *eth;
    uint8_t       *buffer;
    ssize_t        recv_slen;
    uint16_t       l3_proto;

    fprintf(stdout, "[+] Listening started ...\n");

    buffer = (uint8_t *) malloc(mtu + 1);
    /*
     * Attach signal handler 
     */
    signal(SIGINT,  get_signals);
    signal(SIGQUIT, get_signals);
    signal(SIGTERM, get_signals);

    while (1)
    {
        if ((recv_slen = recv(psock, buffer, mtu, 0)) < 0) {
            perror("recv");
            return (-1);
        }

        eth = (struct ethhdr *) buffer;
        /* Only analize IP Packet */
        l3_proto = ntohs(eth->h_proto);
        if (l3_proto != ETH_P_IP && l3_proto != ETH_P_IPV6)
            continue;		

        packet.vxlan       = UNKNOWN;
        packet.headers_len = sizeof(struct ethhdr);
        packet.l3_protocol = l3_proto;
        packet.vxparent    = NULL;
        packet.source      = 0;
        packet.dest        = 0;
        packet.recv_len    = recv_slen;
        
        if (l3_proto == ETH_P_IP) {
            ip = (struct iphdr *) (buffer + sizeof(struct ethhdr));
            process_ip_packet(&packet, ip, tcpfilter, udpfilter, bcastfilter);
        }
        else {
            ip6 = (struct ip6_hdr *) (buffer + sizeof(struct ethhdr));
            process_ip6_packet(&packet, ip6, tcpfilter, udpfilter, 
                               bcastfilter ? 1 : 0);
        }
    }
    return -1;                  /* Should never goes there, exit is by signal */
}


int main(int argc, char **argv)
{
    char                 options;
    int                  promisc;
    int                  mtu;
    int                  ifidx;
    int                  bcf;
    portfilter_t        *tcpfilter;
    portfilter_t        *udpfilter;
    struct sockaddr_ll   sll;
    struct sockaddr_in   brcastfilter;

    bcf        = FALSE;
    tcpfilter  = NULL;
    udpfilter  = NULL;
    ispromisc  = FALSE;
    isprintall = FALSE;
    isprintmsg = FALSE;
    promisc    = FALSE;

    if (argc <= 2)
        help(argv[0], -1);
    else if (strcmp(argv[1], "--help") == 0)
        help(argv[0], 0);

    while ((options = getopt(argc, argv, "XaBpt:u:i:")) != -1) {
        switch (options) {
        case 'p':
            promisc = TRUE;
            break;
        case 'X':
            isprintmsg = TRUE;
            break;
         case 'a':
            isprintall = TRUE;
            break;
        case 'i':
            iface = optarg;
            break;
        case 't':
            tcpfilter = malloc(sizeof(portfilter_t));
            if (build_filter(tcpfilter, optarg) == -1)
                return -1;
            printf("[INFO] TCP filter on, will include ports: ");
            print_portlist(tcpfilter);
            break;
        case 'u':
            udpfilter = malloc(sizeof(portfilter_t));
            if (build_filter(udpfilter, optarg) == -1)
                return -1;
            printf("[INFO] UDP filter on, will include ports: ");
            print_portlist(udpfilter);
            break;
        case 'B':
            bcf = TRUE;
            break;
        default:
            fprintf(stderr, "argument parsing error\n");
            help(argv[0], -1);
            break;

        }
    }

    psock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if ((ifidx = get_if_idx(psock, iface)) < 0) {
        fprintf(stderr,
                "[ERR] Link layer error: Have you specified a valid network interface (\"%s\")?\n And/Or is the program running as root/sudo?\n",
                iface);
        close(psock);
        return -1;
    }
    if ((mtu = get_if_mtu(psock, iface)) < 0) {
        fprintf(stderr,
                "Unable to get interface (\"%s\") MTU, defaulting to 1500\n",
                iface);
        mtu = 1500;

    } else {
        fprintf(stdout, "[+] DETECTED (\"%s\") MTU: %d\n", iface, mtu);
    }

    fprintf(stdout, "[+] RAW SOCKET OK\n");

    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = ifidx;
    sll.sll_protocol = htons(ETH_P_ALL);
    bind(psock, (struct sockaddr *) &sll, sizeof(sll));

    fprintf(stdout, "[+] SOCKET bound to interface (\"%s\") OK\n", iface);


    if (bcf) {
        if (get_broadcast_inet(psock, iface, &brcastfilter) <= 0) {
            fprintf(stderr,
                    "Unable to get interface (\"%s\") Broadcast address\n",
                    iface);
            return -1;
        }
    }

    if (promisc == TRUE) {
        fprintf(stdout, "[+] promiscious mode on: \"%s\"\n", iface);
        if ((set_promisc(psock, iface, TRUE)) == -1) {
            fprintf(stderr,
                    "Unable to set promiscious flag on \"%s\"\n", iface);
            close(psock);
            return -1;
        }
    }

    listenloop(mtu, tcpfilter, udpfilter, bcf ? &brcastfilter : NULL);

    return -1;
}
