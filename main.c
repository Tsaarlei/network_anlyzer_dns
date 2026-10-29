#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <string.h>

// Helper function to print a single byte in 8-bit binary format
void print_binary_byte(unsigned char byte) {
    for (int i = 7; i >= 0; i--) {
        printf("%d", (byte >> i) & 1);
    }
}

int main() {
    int amount_of_packages = 0;
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("Socket creation failed. Use sudo");
        return 1;
    }

    // --- Bind specifically to wlp10s0 ---
    struct sockaddr_ll sll;
    struct ifreq ifr;

    // Safely copy the interface name into the ifreq structure
    snprintf(ifr.ifr_name, IFNAMSIZ, "wlp10s0");

    // Get the interface index mapping for wlp10s0
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("Failed to get interface index. Is wlp10s0 up?");
        close(sock);
        return 1;
    }

    // Set up socket address structure for binding
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("Bind to wlp10s0 failed");
        close(sock);
        return 1;
    }
    // ----------------------------------------

    unsigned char buffer[2048];
    printf("Listening for packets on wlp10s0... Press Ctrl+C to stop.\n\n");

    printf("How many packages to recieve (ans*10) ?");
    if (fgets(buffer, sizeof(buffer), stdin)) {
        amount_of_packages = atoi(buffer)*10;
    }
    ssize_t packet_size = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
    if (packet_size < 0) {
        perror("Recvfrom failed");
        close(sock);
        return 1;
    }

    printf("packet captured (%ld bytes)\n", packet_size);

    int bytes_to_print = (packet_size > amount_of_packages) ? amount_of_packages : packet_size;
    printf("Byte Offset | Hex  | Binary\n");
    printf("------------|------|-----------------\n");

    for (int i = 0; i < bytes_to_print; i++) {
        printf("Byte [%02d]   | 0x%02X | ", i, buffer[i]);
        print_binary_byte(buffer[i]);

        if (i == 5)  printf(" <-- destination MAC ends");
        if (i == 11) printf(" <-- source MAC ends");
        if (i == 13) printf(" <-- Ethernet type");
        printf("\n");
    }

    close(sock);
    return 0;
}
