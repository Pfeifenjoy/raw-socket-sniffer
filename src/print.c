#include "./print.h"
#include <stdio.h>
#include <net/ethernet.h>

#define PRINT_ROW_LENGTH 15

#define YELLOW "\x1B[33m"
#define RESET "\x1B[0m"
#define GRAY "\x1B[90m"
#define RED "\x1B[31m"

//helper functions
void print_mac_address(const u_char *address) {
    short i = 0;
    while(i++ < ETHER_ADDR_LEN - 1) {
        printf("%02x:", address[i]);
    }
    printf("%02x", address[i]);
}

//interface functions
void print_start_message(const char *device) {
    printf("Starting to sniff on device %s ...\n", device);
}

void print_end_message() {
    //this might be triggered by an interrupt
    //therefore the color must be reset, because it might have a different color 
    //when the interrupt is thrown
    printf(RESET);
    printf("\nclosing socket\n");
    printf("stopping sniffing.");
}

void print_error(const char* message) {
    printf(RED);
    printf("%s", message);
    printf(RESET);
}

void print_packet_information(const u_char *packet, const int length) {
    const struct ether_header *header;

    printf("receiving packet of size %d\n", length);
    print_mac_address(header->ether_shost);
    printf(" -> ");
    print_mac_address(header->ether_dhost);
    putchar('\n');
}

void dump(const u_char *packet, const int length) {
    int i = 0; //row iterator

    while(i < length) {
        int j; //column iterator

        j = 0;
        while(j++ < PRINT_ROW_LENGTH) {
            //print hex values if exist
            const int position = i + j;
            if(position < length) {
                printf("%s%02x%s ", YELLOW, packet[position], RESET);
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
                u_char c = packet[position];
                if(c >= 32 && c <= 127) {
                    putchar(c);
                } else {
                    printf(GRAY);
                    putchar('.');
                    printf(RESET);
                }
            }
            else { /* skip */ }
        }

        printf("\n");

        i += PRINT_ROW_LENGTH;
    }

    putchar('\n');
}
