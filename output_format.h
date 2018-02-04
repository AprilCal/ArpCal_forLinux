/****************************************
*					*
*  Create by AprilCal on 2018/1/3.      *
*					*
*****************************************/
#ifndef OUTPUT_FORMAT_H
#define OUTPUT_FORMAT_H

#include <string>
#include <stdlib.h>
using namespace std;
#define red "031"
#define green "032"
#define yellow "033"

//output message without endline.
void output_info(const char* str);
void output_warning(const char* str);
void output_error(const char* str);

//append endline.
void output_info_line(const char* str);
void output_warning_line(const char* str);
void output_error_line(const char* str);

//just output a header
void output_info_header();
void output_warning_header();
void output_error_header();

//output color
void output_with_color(const char* str,const char* color);

//output packet
void output_arp_packet(string str);

//open&close output color
void open_color(const char* color);
void close_color();

//print arp packet
void print_arp_packet(unsigned char* packet);

#endif //OUTPUT_FORMAT_H
