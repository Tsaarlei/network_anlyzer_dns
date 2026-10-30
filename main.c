#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

#include "dns_handler.h"
#include "asciiArtAndStart.h"


int main(void) {
    print_banner();

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket (try sudo)");
        return 1;
    }

    unsigned char buffer[2048];
    printf("Watching DNS queries on all interfaces (Ctrl+C to stop)...\n\n");

    while (1) {
        struct sockaddr_ll from;
        socklen_t fromlen = sizeof(from);
        ssize_t size = recvfrom(sock, buffer, sizeof(buffer), 0,
                                (struct sockaddr *)&from, &fromlen);
        if (size < 0) {
            perror("recvfrom");
            break;
        }

        // only outgoing
        if (from.sll_pkttype != PACKET_OUTGOING) continue;

        char ifname[IF_NAMESIZE] = "?";
        if_indextoname(from.sll_ifindex, ifname);

        if (size < (ssize_t)sizeof(struct ethhdr)) continue;
        struct ethhdr *eth = (struct ethhdr *)buffer;
        uint16_t ethertype = ntohs(eth->h_proto);
        size_t offset = sizeof(struct ethhdr);

        // locate UDP starting
        if (ethertype == ETH_P_IP) {
            if (size < (ssize_t)(offset + sizeof(struct iphdr))) continue;
            struct iphdr *ip = (struct iphdr *)(buffer + offset);
            if (ip->protocol != IPPROTO_UDP || ip->ihl < 5) continue;
            offset += ip->ihl * 4;
        } else if (ethertype == ETH_P_IPV6) {
            if (size < (ssize_t)(offset + sizeof(struct ip6_hdr))) continue;
            struct ip6_hdr *ip6 = (struct ip6_hdr *)(buffer + offset);
            if (ip6->ip6_nxt != IPPROTO_UDP) continue;
            offset += sizeof(struct ip6_hdr);
        } else {
            continue;
        }

        // layer 4 UDP
        if ((size_t)size < offset + sizeof(struct udphdr)) continue;
        struct udphdr *udp = (struct udphdr *)(buffer + offset);
        if (ntohs(udp->uh_dport) != 53) continue;
        offset += sizeof(struct udphdr);

        // layer 7 dns
        handle_dns(buffer + offset, (size_t)size - offset, ifname);
    }

    close(sock);
    return 0;
}