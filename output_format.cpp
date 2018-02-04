#include <iostream>
#include <iomanip>
#include <stdio.h>
#include <time.h>
#include "output_format.h"
using namespace std;

/*
open & close color
for example
open_color(red);
cout
close_color();*/
void open_color(const char* color){
    //cout<<"\033["<<color<<"m";
    printf("\033[%sm",color);
}

void close_color(){
    cout<<"\033[0m";
    //printf("\033[0m");
}

//output message without endline.
void output_info(const char* str){
    time_t tt = time(NULL);
    tm* t= localtime(&tt);
    open_color(green);
    cout<<"["<<t->tm_hour<<":"<<t->tm_min<<":"<<t->tm_sec<<"] [INFO] "<<str;
    //printf("[%02d:%02d:%02d] [INFO] %s", t->tm_hour, t->tm_min, t->tm_sec, str);
    close_color();
}

void output_warning(const char* str){
    time_t tt = time(NULL);
    tm* t= localtime(&tt);
    open_color(yellow);
    cout<<"["<<t->tm_hour<<":"<<t->tm_min<<":"<<t->tm_sec<<"] [WARNING] "<<str;
    //printf("\033[33m[%02d:%02d:%02d] [WARNING] %s\033[0m", t->tm_hour, t->tm_min, t->tm_sec, str);
    close_color();
}

void output_error(const char* str){
    time_t tt = time(NULL);
    tm* t= localtime(&tt);
    open_color(red);
    cout<<"["<<t->tm_hour<<":"<<t->tm_min<<":"<<t->tm_sec<<"] [ERROR] "<<str;
    //printf("[%02d:%02d:%02d] [ERROR] %s", t->tm_hour, t->tm_min, t->tm_sec, str);
    close_color();
}

//append endline.
void output_info_line(const char* str){
    time_t tt = time(NULL);
    tm* t= localtime(&tt);
    open_color(green);
    cout<<"["<<t->tm_hour<<":"<<t->tm_min<<":"<<t->tm_sec<<"] [INFO] "<<str<<endl;
    //printf("[%02d:%02d:%02d] [INFO] %s\n", t->tm_hour, t->tm_min, t->tm_sec, str);
    close_color();
}

void output_warning_line(const char* str){
    time_t tt = time(NULL);
    tm* t= localtime(&tt);
    open_color(yellow);
    cout<<"["<<t->tm_hour<<":"<<t->tm_min<<":"<<t->tm_sec<<"] [WARNING] "<<str<<endl;
    //printf("\033[33m[%02d:%02d:%02d] [WARNING] %s\n\033[0m", t->tm_hour, t->tm_min, t->tm_sec, str);
    close_color();
}

void output_error_line(const char* str){
    time_t tt = time(NULL);
    tm* t= localtime(&tt);
    open_color(red);
    cout<<"["<<t->tm_hour<<":"<<t->tm_min<<":"<<t->tm_sec<<"] [ERROR] "<<str<<endl;
    //printf("\033[31m[%02d:%02d:%02d] [ERROR] %s\n\033[0m", t->tm_hour, t->tm_min, t->tm_sec, str);
    close_color();
}

//just output a header
void output_info_header(){
    time_t tt = time(NULL);
    tm* t= localtime(&tt);
    open_color(green);
    cout<<"["<<t->tm_hour<<":"<<t->tm_min<<":"<<t->tm_sec<<"] [INFO] ";
    close_color();
}
void output_warning_header(){
    time_t tt = time(NULL);
    tm* t= localtime(&tt);
    open_color(yellow);
    cout<<"["<<t->tm_hour<<":"<<t->tm_min<<":"<<t->tm_sec<<"] [WARNING] ";
    close_color();
}
void output_error_header(){
    time_t tt = time(NULL);
    tm* t= localtime(&tt);
    open_color(red);
    cout<<"["<<t->tm_hour<<":"<<t->tm_min<<":"<<t->tm_sec<<"] [ERROR] ";
    close_color();
}

//output with color
void output_with_color(const char* str,const char* color){
    open_color(color);
    cout<<str;
    close_color();
    //printf("\033[%sm%s\033[0m",color,str);
}





//print arp packet
void print_arp_packet(unsigned char* packet)
{
    cout<<"[0x01-0x10] ";
    for(int i=0x0;i<0x10;i++)
    {
	printf("%02x ",packet[i]);
    }
    cout<<endl<<"[0x11-0x20] ";
    for(int i=0x10;i<0x20;i++)
    {
	printf("%02x ",packet[i]);
    }
    cout<<endl<<"[0x21-0x2a] ";
    for(int i=0x20;i<0x2a;i++)
    {
	printf("%02x ",packet[i]);
    }
    cout<<endl;
}
