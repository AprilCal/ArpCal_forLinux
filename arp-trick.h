/****************************************
*					*
*  Create by AprilCal on 2017/5/22.     *
*					*
*****************************************/

#ifndef ARP_TRICK_H
#define ARP_TRICK_H


/*If a parameter is default, those behind it should also be default.*/
void arpTrick(char* ipAddr,char* spoofingIP,int attackTime,const char *timeUnit="second",int intervalTime=500);
/*Parameter 1 is the total time to attack. and parameter 2,
timeUnit, is the time uint of attackTime(totalTime), its 
default value should be second. you can also use other time 
unit such as "minute" or "hour".
parameter 3 is the interval time between two arp packet. 
you'd better leave it default, cause a big enough intervalTime
will lead to invalid attack, and a small intervalTime will 
overload ur device                                       */

void arpTrick(const char* filename);
/*The unique parameter points to a file, containing an arp packet used
  for trick. Through this function, we can use command like this: 
  ArpCal trick <filename>. The format of file is still to be designed.*/

#endif //ARP_TRICK_H
