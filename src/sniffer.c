#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 9000

int main(int argc, char *argv[])
{
    
    int sockfd;

    printf("getting a socket.\n");
    sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);

    if(sockfd == -1) {
        printf("Error: in socket");
        return EXIT_FAILURE;
    }

    printf("Starting to sniff...\n");

    u_char buffer[BUFFER_SIZE];
    int packet = 1;

    while(true) {
        memset(buffer, 0, BUFFER_SIZE);
        printf("listening for the %d. packet...\n", packet++);
        int recv_length = recv(sockfd, buffer, BUFFER_SIZE, 0);
        printf("Got a %d byte packet:\n%s\n", recv_length, buffer);
    }

    return EXIT_SUCCESS;
}
