#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>
#include <pcap.h>
#include "./print.h"

#define BUFFER_SIZE 9000

static volatile bool running = true;
static pcap_t *pcap_handle;

void sigint_handler(int sig) {
    pcap_close(pcap_handle);
    print_end_message();
    exit(EXIT_SUCCESS);
}

void fatal(const char *error_message, const char *error_buffer) {
    print_error("Error: ");
    print_error(error_message);
    print_error("\n");
    print_error("Error Buffer: ");
    print_error(error_buffer);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
    char error_buffer[PCAP_ERRBUF_SIZE];

    const char *device = pcap_lookupdev(error_buffer);
    if(device == NULL) {
        fatal("pcap_lookupdev", error_buffer);
    }

    print_start_message(device);

    pcap_handle = pcap_open_live(device, 4096, 1, 0, error_buffer);
    if(pcap_handle == NULL) {
        fatal("pcap_open_live", error_buffer);
    }
    signal(SIGINT, sigint_handler);

    while(running) {
        struct pcap_pkthdr header;
        const u_char *packet;
        packet = pcap_next(pcap_handle, &header);
        print_packet_information(packet, header.len);
        dump(packet, header.len);
    }


    return EXIT_SUCCESS;
}
