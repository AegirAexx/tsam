#include <iostream>
#include <vector>
#include <algorithm>
#include <cerrno>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <string.h>
#include <arpa/inet.h>
#include <thread>
#include <netinet/ip_icmp.h>
#include <chrono>
#include <iterator>

// Debug -- REMOVE -- REMOVE
void printByteArray(int bufferLength, char buffer[]) {
    for (int i {0}; i < bufferLength; ++i) {
        printf("%02X%s", (uint8_t)buffer[i], (i + 1)%16 ? " " : "\n");
    }
    std::cout << std::endl;
}


// Structures
struct generalPort {
    int portNumber {0};
    bool isReceived {false};

    void initialize (int portNumber){
        this->portNumber = portNumber;
    }
};

struct openPort {
    int portNumber {0};
    bool isReceived {false};
    bool isEvil {false};
    bool isOracle {false};
    bool isPortfwd {false};
    bool isChecksum {false};
    std::string message {0};
    std::string payload {0};

    void initialize (int portNumber){
        this->portNumber = portNumber;
    }
};


struct pseudoHeader {
    u_int32_t sourceAddress;
    u_int32_t destinationAddress;
    u_int8_t placeholder {0};
    u_int8_t protocol {IPPROTO_UDP};
    u_int16_t udpLength;

    void initialize(u_int32_t sourceAddress, u_int32_t destinationAddress, u_int16_t udpLength){
        this->sourceAddress = sourceAddress;
        this->destinationAddress = destinationAddress;
        this->udpLength = udpLength;
    }
};

// Functions prototypes.
void sendPacket(int portlow, int porthigh, std::string destinationAddress, bool &isSent);
void recievePacket(int portlow, std::string sourceAddress, bool &isSent, std::vector<generalPort> &generalPorts);
void sendOpenPorts(std::string destinationAddress, std::string sourceAddress, bool &isSent, std::vector<openPort> &openPorts);
void recieveOpenPorts(std::string sourceAddress, bool &isSent, std::vector<openPort> &openPorts);
unsigned short csum(unsigned short *ptr, int nbytes);
iphdr * generateHeaderIP(char datagram[], std::string sourceAddress,  sockaddr_in socketAddress, openPort port, std::string data);
udphdr * generateHeaderUPD(char datagram[], std::string sourceAddress,  sockaddr_in socketAddress, openPort port, std::string data);


// Main program.
int main(int argc, char* argv[]) {

    // Check user input arguments.
    if(argc != 5) {
        std::cout << "Usage: ./scanner [source IP] [destination IP] [port low] [port high]" << std::endl;
        exit(0);
    }

    bool isSent {false};

    // Variables for user input arguments.
    std::string sourceAddress (argv[1]);
    std::string destinationAddress (argv[2]);
    int portLow {atoi(argv[3])};
    int portHigh {atoi(argv[4])};


    // Check port range.
    if(portLow > portHigh) {
        std::cout << "Enter the lower port before the higher port" << std::endl;
        std::cout << "Usage: ./scanner [source IP] [destination IP] [port low] [port high]" << std::endl;
        exit(0);
    }

    // Keys initializeialization of the <vector> with port numbers.
    std::vector<generalPort> generalPorts;
    for(int i {portLow}; i <= portHigh; ++i) {
        generalPort thisPort;
        thisPort.initialize(i);
        generalPorts.push_back(thisPort);
    }

    // First pair of theads to send and recieve packets.
    std::thread firstSendThread (sendPacket, portLow, portHigh, destinationAddress, std::ref(isSent));
    std::thread firstRecieveThread (recievePacket, portLow, sourceAddress, std::ref(isSent), std::ref(generalPorts));
    firstSendThread.join();
    firstRecieveThread.join();

    // Reset control flag.
    isSent = false;

    // Keys initializeialization of the <vector> with port numbers.
    std::vector<openPort> openPorts;
    for(size_t i {0}; i < generalPorts.size(); ++i) {
        if(generalPorts.at(i).isReceived == false) {
            openPort thisPort;
            thisPort.portNumber = generalPorts.at(i).portNumber;
            openPorts.push_back(thisPort);
        }
    }

    for(size_t i {0}; i < openPorts.size(); ++i) {
        std::cout << "Open Port is# " << openPorts.at(i).portNumber << std::endl;
    }

    // Second pair of theads to send and recieve packets.
    std::thread secondSendThread (sendOpenPorts, destinationAddress, sourceAddress, std::ref(isSent), std::ref(openPorts));
    std::thread secondRecieveThread (recieveOpenPorts, sourceAddress, std::ref(isSent), std::ref(openPorts));
    secondSendThread.join();
    secondRecieveThread.join();

    return 0;
}


void sendPacket(int portlow, int porthigh, std::string destinationAddress, bool &isSent ) {
    int sendSocket {0};
    std::string data = "knock";

    for(int port {portlow}; port <= porthigh; ++port) {
        sockaddr_in socketAddress;
        socketAddress.sin_family = AF_INET;
        socketAddress.sin_port = htons(port);
        inet_pton(AF_INET, destinationAddress.c_str(), &socketAddress.sin_addr);

        sendSocket = socket(
            AF_INET,
            SOCK_RAW,
            IPPROTO_RAW
        );

        if(sendSocket < 0) {
            std::perror("### Create socket failed");
        }

        for(int i {0}; i < 5; ++i) {
            sendto(
                sendSocket,
                data.c_str(),
                data.size(),
                0,
                NULL,
                0
            );
            std::this_thread::sleep_for(std::chrono::milliseconds(125));
        }
    }
    isSent = true;
}

void recievePacket(int portlow, std::string sourceAddress, bool &isSent, std::vector<generalPort> &generalPorts) {
    int recieveSocket {0};
    int boundedSocket {0};
    int receivedData {-1};
    unsigned int receivedLen {0};
    char buffer[1024] {0};

    while(!isSent) {
        sockaddr_in socketAddress;
        socketAddress.sin_family = AF_INET;
        socketAddress.sin_port = htons(50000);
        inet_pton(AF_INET, sourceAddress.c_str(), &socketAddress.sin_addr);

        recieveSocket = socket(
            AF_INET,
            SOCK_RAW,
            IPPROTO_ICMP
        );

        if(recieveSocket < 0) {
            std::perror("### Create socket failed");
        }

        boundedSocket = bind(
            recieveSocket,
            (struct sockaddr *) &socketAddress,
            sizeof(struct sockaddr_in)
        );

        if(boundedSocket < 0) {
            std::perror("### Failed to bind");
        }

        struct timeval timeout;
            timeout.tv_sec = 5;
            timeout.tv_usec = 0;
        int setSockOpt = setsockopt(recieveSocket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));

        if(setSockOpt < 0) {
            std::perror("### setsockopt() failed.");
        }

        receivedData = recvfrom(
            recieveSocket,
            buffer,
            1024,
            0,
            (struct sockaddr *) &socketAddress,
            &receivedLen
        );

        if(receivedData > 0) {
            short *portPtr {(short *)&buffer[50]};
            int currentPort {htons(*portPtr)};
            int index {currentPort - portlow};
            unsigned char *codeICMP {(unsigned char*) &buffer[21]};
            int code {((htons(*codeICMP) >> 8) & 0xffff)};
            if(code == 3 && !generalPorts.at(index).isReceived) {
                generalPorts.at(index).isReceived = true;
            }
        }
        memset(buffer, 0, 1024);
    }
}


iphdr * generateHeaderIP(char datagram[], std::string sourceAddress,  sockaddr_in socketAddress, openPort port, std::string data) {

    struct iphdr *ipHeader = (struct iphdr *) datagram;

    ipHeader->ihl = 5;
    ipHeader->version = 4;
    ipHeader->tos = 0;
    ipHeader->id = htonl (54321);
    ipHeader->ttl = 255;

    ipHeader->protocol = IPPROTO_UDP;
    ipHeader->saddr = inet_addr(sourceAddress.c_str());
    ipHeader->daddr = socketAddress.sin_addr.s_addr;

    // ipHeader->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + data.size();
    ipHeader->check = csum((unsigned short *) datagram, ipHeader->tot_len);

    if(port.isEvil){
        ipHeader->frag_off |= htons(0x8000);
    } else {
        ipHeader->frag_off = 0;
    }
    return ipHeader;
}


udphdr * generateHeaderUPD(char datagram[], std::string sourceAddress,  sockaddr_in socketAddress, openPort port, std::string data) {
    struct udphdr *udpHeader = (struct udphdr *) (datagram + sizeof (struct iphdr));

    udpHeader->source = htons(50000);
    udpHeader->dest = htons(port.portNumber);
    udpHeader->len = htons(8 + data.size());
    udpHeader->check = 0;


    return udpHeader;
}

void sendOpenPorts(std::string destinationAddress, std::string sourceAddress, bool &isSent, std::vector<openPort> &openPorts) {

    int sendSocket {0};
    std::string data = "knock";

    for(size_t port {0}; port < openPorts.size(); ++port) {

        sockaddr_in socketAddress;
        socketAddress.sin_family = AF_INET;
        socketAddress.sin_port = htons(port);
        inet_pton(AF_INET, destinationAddress.c_str(), &socketAddress.sin_addr);

        sendSocket = socket(
            AF_INET,
            SOCK_RAW,
            IPPROTO_RAW
        );

        if(sendSocket < 0) {
            std::perror("### Create UDP_socket failed");
        }

        int val {1};
        int setSockOpt = setsockopt(
            sendSocket,
            IPPROTO_IP,
            IP_HDRINCL,
            &val, sizeof(val)
        );

        if(setSockOpt < 0) {
            std::perror("### setsockopt() failed");
            exit(0);
        }

        char datagram[4096] {0};
        std::string data = datagram + sizeof(struct iphdr) + sizeof (struct udphdr);
        int pseudogramSize = sizeof(struct pseudoHeader) + sizeof(struct udphdr) + data.size();
        char *pseudogram = (char*) malloc(pseudogramSize);

        // IP HEADER
        // generateHeaderIP();

        // UDP HEADER
        // generateHeaderUPD();

        struct pseudoHeader pseudoHeader;

        pseudoHeader.initialize(
            inet_addr(sourceAddress.c_str()),
            socketAddress.sin_addr.s_addr,
            htons(sizeof(struct udphdr) + data.size())
        );

        memcpy(
            pseudogram,
            (char*) &pseudoHeader,
            sizeof (struct pseudoHeader)
        );

        memcpy(
            pseudogram + sizeof(struct pseudoHeader),
            generateHeaderUPD( datagram, sourceAddress, socketAddress, openPorts.at(port), data),
            sizeof(struct udphdr) + data.size()
        );

        struct udphdr *udpHeader  = (struct udphdr *) (datagram + sizeof (struct iphdr));

        bool isChecksum = false;

        if(isChecksum){
            udpHeader->check = csum((unsigned short*) pseudogram , pseudogramSize);
        } else {
            udpHeader->check = csum((unsigned short*) pseudogram , pseudogramSize);
        }

        for(int i {0}; i < 5; ++i) {
            sendto(
                sendSocket,
                datagram,
                sizeof(struct iphdr) + sizeof(struct udphdr) + data.size(),
                MSG_CONFIRM,
                (const struct sockaddr *) &socketAddress,
                sizeof(socketAddress)
            );
            std::this_thread::sleep_for(std::chrono::milliseconds(125));
        }
        free(pseudogram);
    }
    isSent = true;
}

void recieveOpenPorts(std::string sourceAddress, bool &isSent, std::vector<openPort> &openPorts) {

    int recieveSocket {0};
    int boundedSocket {0};
    int receivedData {-1};
    unsigned int receivedLen {0};
    char buffer[1024] {0};
    char *data;

    while(!isSent) {

        sockaddr_in socketAddress;
        socketAddress.sin_family = AF_INET;
        socketAddress.sin_port = htons(50000);
        inet_pton(AF_INET, sourceAddress.c_str(), &socketAddress.sin_addr);

        recieveSocket = socket(
            AF_INET,
            SOCK_RAW,
            IPPROTO_UDP
        );

        if(recieveSocket < 0) {
            std::perror("### Create socket failed");
        }

        boundedSocket = bind(
            recieveSocket,
            (struct sockaddr *) &socketAddress,
            sizeof(struct sockaddr_in)
        );

        if(boundedSocket < 0) {
            std::perror("### Failed to bind");
        }

        struct timeval timeout;
            timeout.tv_sec = 2;
            timeout.tv_usec = 0;

        int setSockOpt = setsockopt(
            recieveSocket,
            SOL_SOCKET,
            SO_RCVTIMEO,
            (char *)&timeout,
            sizeof(timeout)
        );

        if(setSockOpt < 0) {
            std::perror("### setsockopt() failed");
        }

        receivedData = recvfrom(
            recieveSocket,
            buffer,
            1024,
            0,
            (struct sockaddr *) &socketAddress,
            &receivedLen
        );

        if(recieveSocket > 0) {
            short *portPtr {(short *)&buffer[20]};
            int sourcePort {htons(*portPtr)};
            data = buffer + sizeof(struct iphdr) + sizeof (struct udphdr);

            int index {0};
            for(size_t i {0}; i < openPorts.size(); ++i) {
                if(openPorts.at(i).portNumber == sourcePort) {
                    index = i;
                }
            }

            if(!openPorts.at(index).isReceived) {
                openPorts.at(index).isReceived = true;
                openPorts.at(index).message = data;
            }

            // TODO:
            // Herna finnum vid ut hver er hvad, isEvil, isOracle, isPortMongo, isChecksum
        }
        memset(buffer, 0, 1024);
    }
}

unsigned short csum(unsigned short *ptr, int nbytes) {
    long sum {0};
    unsigned short oddbyte {0};
    short answer {0};

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