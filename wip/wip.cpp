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
#include <bitset>

// Functions prototypes.
void printArguments(int argc, char* argv[]);

int main(int argc, char* argv[]){

    // printArguments(argc, argv);
    char d[4096];

    std::cout << sizeof(d) << std::endl;

    return 0;
}

// Prints out arguments.
void printArguments(int argc, char* argv[]){
    std::cout << "\nArguments to the program:" << std::endl;
    for(int i = 0; i < argc; ++i){
        std::cout << "#" << i << " is " << argv[i] << std::endl;
    }
}

// for(auto x: UDP_buffer) std::cout << UDP_buffer[x];

// std::cout << "--------------------" << std::endl;



