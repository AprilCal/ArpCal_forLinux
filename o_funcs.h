#ifndef O_FUNCS_H
#define O_FUNCS_H
#include <stdlib.h>
#include <iostream>
using namespace std;
#define NORETURN __attribute__ ((__noreturn__))

/* Print error message and exit. For backwords compatibility.
   In case we will need _exit() instead of exit().          */
void NORETURN output_error_msg_and_exit(const char* msg,int errorCode);

#endif
