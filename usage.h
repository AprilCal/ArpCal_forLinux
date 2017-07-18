#ifndef USAGE_H
#define USAGE_H

const char* usageString[]={"Usage: ArpCal <command> [args]\t",
                           "       ArpCal <trick> <target ip> <time> [second|minute|hour] [interval time]\t",
			   "       ArpCal <list> [-v]                                                    \t"};

void printUsage();

#endif //USAGE_H
