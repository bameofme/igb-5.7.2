#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/if_packet.h>

// Function to calculate checksum for UDP packet
unsigned short checksum(unsigned short *buf, int len) {
    unsigned long sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(unsigned char *)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

int main() {
    int sockfd;
    struct sockaddr_ll dest_addr;
    char packet[ETH_FRAME_LEN];
    struct ethhdr *eth_header = (struct ethhdr *)packet;
    struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));
    struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
    char *dhcp_data = packet + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd == -1) {
        perror("socket");
        return 1;
    }

    memset(packet, 0, sizeof(packet));

    dest_addr.sll_family = AF_PACKET;
    dest_addr.sll_protocol = htons(ETH_P_ALL);
    dest_addr.sll_ifindex = if_nametoindex("dummy_eth");
    dest_addr.sll_halen = ETH_ALEN;

    // Destination MAC address (Broadcast)
    dest_addr.sll_addr[0] = 0xff;
    dest_addr.sll_addr[1] = 0xff;
    dest_addr.sll_addr[2] = 0xff;
    dest_addr.sll_addr[3] = 0xff;
    dest_addr.sll_addr[4] = 0xff;
    dest_addr.sll_addr[5] = 0xff;

    // Source MAC address (00:1b:21:36:bd:65)
    sscanf("00:1b:21:36:bd:65", "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &eth_header->h_source[0], &eth_header->h_source[1], &eth_header->h_source[2],
           &eth_header->h_source[3], &eth_header->h_source[4], &eth_header->h_source[5]);

    // Ethernet type (IPv4)
    eth_header->h_proto = htons(ETH_P_IP);

    // IP header
    ip_header->ihl = 5;
    ip_header->version = 4;
    ip_header->tos = 0x10; // TOS field with DSCP: CS1 (0x10)
    ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + strlen(dhcp_data));
    ip_header->id = 0;
    ip_header->frag_off = 0;
    ip_header->ttl = 128;
    ip_header->protocol = IPPROTO_UDP;
    ip_header->saddr = inet_addr("0.0.0.0"); // Source IP address (0.0.0.0)
    ip_header->daddr = inet_addr("255.255.255.255"); // Destination IP address (255.255.255.255)

    // UDP header
    udp_header->source = htons(68); // Source port (BOOTP client: 68)
    udp_header->dest = htons(67); // Destination port (BOOTP server: 67)
    udp_header->len = htons(sizeof(struct udphdr) + strlen(dhcp_data));
    udp_header->check = 0; // Set to zero for no checksum calculation

    // DHCP Data (payload)
    strcpy(dhcp_data, "aaaaaaaaaaaaa hello");

    udp_header->check = checksum((unsigned short *)udp_header, sizeof(struct udphdr) + strlen(dhcp_data) + 12); // Add 12 for the pseudo-header checksum

    int frame_len = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + strlen(dhcp_data);

    // Send the packet
    ssize_t bytes_sent = sendto(sockfd, packet, frame_len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (bytes_sent == -1) {
        perror("sendto");
        close(sockfd);
        return 1;
    }

    printf("Packet sent successfully! Sent %zd bytes.\n", bytes_sent);

    close(sockfd);
    return 0;
}
