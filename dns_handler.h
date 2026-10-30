//
// Created by pave on 30/10/2026.
//

#ifndef SNIFFER_DNS_HANDLER_H
#define SNIFFER_DNS_HANDLER_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>

static const char *type_name(uint16_t t) {
    switch (t) {
        case 1:  return "IPv4 / A";
        case 28: return "IPv6 / AAAA";
        case 5:  return "CNAME";
        case 15: return "MX";
        case 16: return "TXT";
        case 65: return "HTTPS";
        default: return "?";
    }
}

static void handle_dns(const unsigned char *dns, size_t len, const char *ifname) {
    if (len < 12) return;

    uint16_t flags = (dns[2] << 8) | dns[3];
    if (flags & 0x8000) return;
    uint16_t questions = (dns[4] << 8) | dns[5];
    if (questions < 1) return;

    char name[256];
    size_t n = 0, pos = 12;
    int terminated = 0;

    while (pos < len) {
        unsigned char label_len = dns[pos++];
        if (label_len == 0) { terminated = 1; break; }
        if (label_len & 0xC0) return;
        if (pos + label_len > len || n + label_len + 1 >= sizeof(name)) return;
        memcpy(name + n, dns + pos, label_len);
        n += label_len;
        name[n++] = '.';
        pos += label_len;
    }
    if (!terminated || pos + 4 > len) return;

    if (n > 0) n--;
    name[n] = '\0';

    uint16_t qtype = (dns[pos] << 8) | dns[pos + 1];
    printf("[%s] %-12s %s\n", ifname, type_name(qtype), n ? name : ".");
}
#endif //SNIFFER_DNS_HANDLER_H
