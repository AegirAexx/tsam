// #include <iostream>
// #include <sys/types.h>
// #include <sys/socket.h>
// #include <string.h>
// #include <unistd.h>
// #include <netdb.h>
// #include <arpa/inet.h>
// #include <netinet/ip.h>
// #include <netinet/udp.h>
// #include <string>
// #include <vector>
// #include <chrono>
// #include <thread>
// #include <stdio.h>
// #include <bitset>

// // Functions prototypes.
// void printArguments(int argc, char* argv[]);

// int main(int argc, char* argv[]){

//     // printArguments(argc, argv);
//     char d[4096];

//     std::cout << sizeof(d) << std::endl;

//     return 0;
// }

// // Prints out arguments.
// void printArguments(int argc, char* argv[]){
//     std::cout << "\nArguments to the program:" << std::endl;
//     for(int i = 0; i < argc; ++i){
//         std::cout << "#" << i << " is " << argv[i] << std::endl;
//     }
// }

// for(auto x: UDP_buffer) std::cout << UDP_buffer[x];

// std::cout << "--------------------" << std::endl;


// #include <iostream>
// #include <fstream>
// #include <string>
// #include <vector>
// #include <stdlib.h>

// std::string getIP() {

//     system("hostname -I | cut -d \" \" -f 1 > ip.txt");

//     std::string ipNumber;
//     std::ifstream syscall;
//     std::vector<std::string> ipS;

//     syscall.open("ip.txt");
//     while (std::getline(syscall, ipNumber)){
//         ipS.push_back(ipNumber);
//     }
//     syscall.close();

//     return ipS.at(0);
// }


// regex_search example
#include <iostream>
#include <string>
#include <regex>

int main ()
{
    std::string str1("This is the port:4080");
    std::string str2("I am the oracle, reveal to me the hidden ports, and I shall show you the way.");
    std::string str3("Please send me a message with a valid udp checksum with value of 61453");
    std::string str4("I only speak with fellow evil villains. (https://en.wikipedia.org/wiki/Evil_bit)");

    std::smatch match1;
    std::smatch match2;
    std::smatch match3;
    std::smatch match4;

    std::regex exp1("[0-9]");
    std::regex exp2("oracle");
    std::regex exp3("[0-9]");
    std::regex exp4("evil");

    std::string retStr1;
    std::string retStr2;
    std::string retStr3;
    std::string retStr4;

    std::cout << "------------------------------------------------" << std::endl;


    std::cout << "Target sequence: " << str1 << std::endl;
    std::cout << "Regular expression: /[0-9]/" << std::endl;
    std::cout << "The following matches and submatches were found:" << std::endl;


    while (std::regex_search (str1,match1,exp1)) {
        for (auto x1:match1) retStr1 += x1;
        str1 = match1.suffix().str();
    }

    std::cout << "Number found: " << retStr1 << std::endl;

    std::cout << "------------------------------------------------" << std::endl;

    std::cout << "Target sequence: " << str2 << std::endl;
    std::cout << "Regular expression: /oracle/" << std::endl;
    std::cout << "The following matches and submatches were found:" << std::endl;


    while (std::regex_search (str2,match2,exp2)) {
        for (auto x2:match2) retStr2 += x2;
        str2 = match2.suffix().str();
    }

    std::cout << "Number found: " << retStr2 << std::endl;

    std::cout << "------------------------------------------------" << std::endl;


    std::cout << "Target sequence: " << str3 << std::endl;
    std::cout << "Regular expression: /[0-9]/" << std::endl;
    std::cout << "The following matches and submatches were found:" << std::endl;


    while (std::regex_search (str3,match3,exp3)) {
        for (auto x3:match3) retStr3 += x3;
        str3 = match3.suffix().str();
    }

    std::cout << "Number found: " << retStr3 << std::endl;


    std::cout << "------------------------------------------------" << std::endl;

    std::cout << "Target sequence: " << str4 << std::endl;
    std::cout << "Regular expression: /evil/" << std::endl;
    std::cout << "The following matches and submatches were found:" << std::endl;


    while (std::regex_search (str4,match4,exp4)) {
        for (auto x4:match4) retStr4 += x4;
        str4 = match4.suffix().str();
    }

    std::cout << "Number found: " << retStr4 << std::endl;



    return 0;
}