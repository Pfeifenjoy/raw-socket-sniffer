#pragma once
#ifndef PRINT_H_MUU2YWSR
#define PRINT_H_MUU2YWSR
#include <pcap.h>

void print_start_message(const char*);
void print_end_message();
void print_error(const char*);
void print_packet_information(const u_char*, const int);
void dump(const u_char *, const int);

#endif /* end of include guard: PRINT_H_MUU2YWSR */
