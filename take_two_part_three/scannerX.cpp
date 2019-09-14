#include <iostream>
#include <vector>
#include <algorithm>
#include <cerrno>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <string.h>
#include <arpa/inet.h>


// Structures
struct openPort{
    int port;
    std::string message;

    // Member function to initialize the datatype (constructor).
    void init (int port, std::string message) {
        this->port = port;
        this->message = message;
    }
};


// Functions prototypes.
void udpBasic(int portlow, int porthigh, std::string destinationAddress);

void icmpBasic(int portlow, int porthigh, std::string destinationAddress);

void printByteArray(int bufferLength, char buffer[]);


// Main program.
int main(int argc, char* argv[]){

    // Check user input arguments.
    if(argc != 5){
        std::cout << "Usage: ./scanner [source IP] [destination IP] [port low] [port high]" << std::endl;
        exit(0);
    }

    // Variables for user input arguments.
    std::string sourceAddress (argv[1]);
    std::string destinationAddress (argv[2]);
    int portlow {atoi(argv[3])};
    int porthigh {atoi(argv[4])};

    // Check port range.
    if(portlow > porthigh) {
        std::cout << "Enter the lower port before the higher port" << std::endl;
        std::cout << "Usage: ./scanner [source IP] [destination IP] [port low] [port high]" << std::endl;
        exit(0);
    }

    std::vector<openPort> openPorts;

    // Basic UPD - Works on known ports.
    // udpBasic(portlow, porthigh, destinationAddress);

    // Basic ICMP - Works on known ports.
    icmpBasic(portlow, porthigh, destinationAddress);

    return 0;
}


void udpBasic(int portlow, int porthigh, std::string destinationAddress){

    int UDP_socket {0};
    int UDP_received {-1};
    unsigned int UDP_received_len {0};
    int UDP_bound {0};
    int UDP_delivered {0};
    char UDP_buffer[1024] {0};

    for(int port {portlow}; port <= porthigh; port++){

        sockaddr_in socketAddress;
        socketAddress.sin_family = AF_INET;
        socketAddress.sin_port = htons(port);
        inet_pton(AF_INET, destinationAddress.c_str(), &socketAddress.sin_addr);

        UDP_socket = socket(
            AF_INET,
            SOCK_DGRAM,
            0
        );

        if(UDP_socket < 0){
            std::perror("### Create socket failed");
        }

        UDP_bound = bind(
            UDP_socket,
            (struct sockaddr *) &socketAddress,
            sizeof(struct sockaddr_in)
        );

        if(UDP_bound < 0){
            std::perror("### Failed to bind");
        }

        UDP_delivered = sendto(
            UDP_socket,
            "knock",
            5,
            0, // --MSG_CONFIRM?
            (const struct sockaddr *) &socketAddress,
            sizeof(socketAddress)
        );

        std::cout << "Packet size delivered: " << UDP_delivered << std::endl;

        UDP_received = recvfrom(
            UDP_socket,
            UDP_buffer,
            1024,
            0,
            (struct sockaddr *) &socketAddress,
            &UDP_received_len
        );

        std::cout << "Response length:  " << UDP_received << std::endl;
        std::cout << "Response: " << UDP_buffer << std::endl;

        memset(UDP_buffer, 0, 1024);

    }

}


void icmpBasic(int portlow, int porthigh, std::string destinationAddress){

    int UDP_socket {0};
    int ICMP_socket {0};
    int ICMP_received {-1};
    unsigned int ICMP_received_len {0};
    int ICMP_delivered {0};
    char ICMP_buffer[1024] {0};

    for(int port {portlow}; port <= porthigh; port++){

        sockaddr_in socketAddress;
        socketAddress.sin_family = AF_INET;
        socketAddress.sin_port = htons(port);
        inet_pton(AF_INET, destinationAddress.c_str(), &socketAddress.sin_addr);

        UDP_socket = socket(
            AF_INET,
            SOCK_DGRAM,
            0
        );

        ICMP_socket = socket(
            AF_INET,
            SOCK_RAW,
            IPPROTO_ICMP
        );

        if(UDP_socket < 0){
            std::perror("### Create UDP_socket failed");
        }

        if(ICMP_socket < 0){
            std::perror("### Create ICMP_socket failed");
        }


        ICMP_delivered = sendto(
            UDP_socket,
            "knock",
            5,
            0,
            (const struct sockaddr *) &socketAddress,
            sizeof(socketAddress)
        );

        std::cout << "Packet size delivered: " << ICMP_delivered << std::endl;

        ICMP_received = recvfrom(
            ICMP_socket,
            ICMP_buffer,
            1024,
            0,
            (struct sockaddr *) &socketAddress,
            &ICMP_received_len
        );

        std::cout << "Response length:  " << ICMP_received << std::endl;

        std::cout << "Response: " << std::endl;;
        printByteArray(ICMP_received, ICMP_buffer);



        memset(ICMP_buffer, 0, 1024);

    }
}

void printByteArray(int bufferLength, char buffer[]){

    for (int i {0}; i < bufferLength; i++) {
        printf("%02X%s", (uint8_t)buffer[i], (i + 1)%16 ? " " : "\n");
    }
    std::cout << std::endl;
}