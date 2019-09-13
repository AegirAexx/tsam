#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include <stdio.h>

// Checksum function from the internetz
unsigned short csum(unsigned short *ptr, int nbytes){
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum = 0;

    while(nbytes > 1){
        sum += *ptr++;
        nbytes -= 2;
    }

    if(nbytes == 1){
        oddbyte = 0;
        *((u_char*) &oddbyte) = *(u_char*) ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short) ~sum;

    return(answer);
}

int main(int argc, char* argv[]){

    // CHECKSUM PLAYGROUND

    return 0;
}