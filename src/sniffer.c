#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <pcap.h>

#define BUFFER_SIZE 9000
#define PRINT_ROW_LENGTH 15

static volatile bool running = true;
static pcap_t *pcap_handle;

void sigint_handler(int sig) {
    printf("closing sockets.");
    pcap_close(pcap_handle);
    exit(EXIT_SUCCESS);
}

void print_receive_packet(const u_char *packet, int length) {
    printf("receiving package of length: %d\n", length);

    int i = 0; //row iterator

    while(i < length) {
        int j; //column iterator

        j = 0;
        while(j++ < PRINT_ROW_LENGTH) {
            //print hex values if exist
            const int position = i + j;
            if(position < length) {
                printf("%02x ", packet[position]);
            } else {
                printf("   "); // fill up
            }
        }

        //seperator
        printf("| ");

        j = 0;
        while(j++ < PRINT_ROW_LENGTH) {
            //print character values
            const int position = i + j;
            if(position < length) {
                printf("%c", packet[position]);
            }
            else { /* skip */ }
        }

        printf("\n");

        i += PRINT_ROW_LENGTH;
    }
}

void fatal(const char *error_message, const char *error_buffer) {
    printf("Error: %s\n", error_message);
    printf("Error Buffer: %s", error_buffer); 
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
    struct pcap_pkthdr header;
    const u_char *packet;

    char error_buffer[PCAP_ERRBUF_SIZE];

    char *device;

    memset(error_buffer, 0, PCAP_ERRBUF_SIZE);
    device = pcap_lookupdev(error_buffer);

    if(device == NULL) {
        fatal("pcap_lookupdev", error_buffer);
    }

    printf("Starting to sniff on device %s ...\n", device);

    memset(error_buffer, 0, PCAP_ERRBUF_SIZE);
    pcap_handle = pcap_open_live(device, 4096, 1, 0, error_buffer);

    if(pcap_handle == NULL) {
        fatal("pcap_open_live", error_buffer);
    }

    signal(SIGINT, sigint_handler);

    while(running) {
        packet = pcap_next(pcap_handle, &header);
        print_receive_packet(packet, header.len);
    }


    return EXIT_SUCCESS;
}
