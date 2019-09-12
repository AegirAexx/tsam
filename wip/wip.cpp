#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string>
#include <vector>
#include <chrono>
#include <thread>
// WIP
#include <net/ethernet.h>

int main(int argc, char* argv[])
{
    if(argc != 4){
        std::cout << "Usage: client [ip] [portlow] [porthigh]" << std::endl;
        exit(0);
    }

    int portlow = atoi(argv[2]);
    int porthigh = atoi(argv[3]);

    if(portlow > porthigh) {
        std::cout << "Enter low port before high port" << std::endl;
        std::cout << "Usage: client [ip] [portlow] [porthigh]" << std::endl;
        exit(0);
    }

    std::string message = "knock";

    int UDP_sock;
    int ICMP_sock;
    int recvsock;

    std::string ipAddress = argv[1];

    char ICMPResponse[512];

    memset(ICMPResponse, 0x41, 512);

    std::cout << "ICMPResponse init: \n -------------------------\n" << ICMPResponse << std::endl;

    int ICMP_received {0};

    for(int i = portlow; i <= porthigh; i++){

        UDP_sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
        ICMP_sock = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK , IPPROTO_ICMP);
        // WIP - PACKET(7)
        // recvsock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        recvsock = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL));

        std::cout << "------------------" << std::endl;
        std::cout << "UDP_sock: " << UDP_sock << " | ICMP_sock: " << ICMP_sock << " | recvsock: " << recvsock << std::endl;

        if (UDP_sock < 0) {
            perror("Can't create a UDP socket");
            return -1;
        }

        if (ICMP_sock < 0) {
            perror("Can't create a ICMP socket");
            return -1;
        }

        // WIP
        if (recvsock < 0) {
            perror("Can't create a recvsock socket");
            return -1;
        }

        memset(ICMPResponse, 0, 512);

        sockaddr_in sk_addr;
        sk_addr.sin_family = AF_INET;
        sk_addr.sin_port = htons(i);
        inet_pton(AF_INET, ipAddress.c_str(), &sk_addr.sin_addr);

        ICMP_received = -1;

        std::cout << "------------------" << std::endl;
        std::cout << "port: " << i << std::endl;
        std::cout << "------------------" << std::endl;

        int send{0};
        for(int x = 0; x < 5; ++x){

            std::cout << "send #" << x << std::endl;

            send = sendto(UDP_sock, message.c_str(), message.size(), MSG_CONFIRM, (const struct sockaddr *) &sk_addr, sizeof(sk_addr));

            std::cout << "send_int: " << send << std::endl;

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        for(int y = 1;ICMP_received != -1; ++y){
            // ICMP_received = recvfrom(ICMP_sock, ICMPResponse, 512, 0, NULL,  NULL);
            // WIP
            ICMP_received = recvfrom(recvsock, ICMPResponse, 512, 0, NULL,  NULL);
            std::cout << "atempt #" << y << std::endl;
        }

        std::cout << "output from ICMP_received: " << ICMP_received << std::endl;
        std::cout << "output from ICMPResponse: " << ICMPResponse << std::endl;

        // Close the sockets
        close(UDP_sock);
        close(ICMP_sock);
        // WIP
        close(recvsock);

    }

    return 0;
}