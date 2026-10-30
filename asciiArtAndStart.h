//
// Created by pave on 30/10/2026.
//

#ifndef SNIFFER_ASCIIARTANDSTART_H
#define SNIFFER_ASCIIARTANDSTART_H
static void print_banner(void) {
    static const char *art[] = {
        " ____  _   _ ____",
        "|  _ \\| \\ | / ___|",
        "| | | |  \\| \\___ \\",
        "| |_| | |\\  |___) |",
        "|____/|_| \\_|____/",
        "   s n i f f e r",
        "",
        "  [you] ==[ A? www.youtube.com ]==>>> (the internet)",
        "  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~",
        "        watching UDP port 53 on every interface",
        "",
    };
    for (size_t i = 0; i < sizeof(art) / sizeof(art[0]); i++)
        puts(art[i]);
}
static void start(void) {
    
}
#endif //SNIFFER_ASCIIARTANDSTART_H
