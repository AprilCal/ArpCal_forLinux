#include "o_funcs.h"
void NORETURN output_error_msg_and_exit(const char* msg,int errorCode)
{ 
    cout<<msg<<endl;
    exit(errorCode);
}


