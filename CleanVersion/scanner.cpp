// COM: dagur17@ru.is & aegir15@ru.is - Reykjavik University - 2019.
// COM: UDP port scanner for T-409-TSAM Assignment 3 / Project 2.

#include <iostream>
#include <vector>
#include <fstream>
#include <regex>
#include <thread>
#include <chrono>
#include <cerrno>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>


// COM: Port datatypes.
struct port {
    int portNumber {0};
    bool isReceived = false;
    void initialize (int portNumber) {
        this->portNumber = portNumber;
    }
};

struct openPort {
    int portNumber;
    // COM: Payload for ports.
    std::string message {0};
    std::string payload {0};
    std::string secretPhrase {0};
    std::string checkSum {0};
    // COM: Boolean flags to track them through conditional logic.
    bool isEvil {false};
    bool isKnock {false};
    bool isSecret {false};
    bool isOracle {false};
    bool isPortfwd {false};
    bool isChecksum {false};
    bool isReceived {false};
    bool isLastStand {false};
    bool isFinalMessage {false};
    bool isMasterOfTheUniverse {false};
    void initialize (int portNumber) {
        this->portNumber = portNumber;
    }
};

struct pseudo_header {
    // COM: Unsigned datatypes.
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t udp_length;
};

// COM: Functions prototypes.
void recvPacket(int portlow, std::string sourceAddress, bool &isSent, std::vector<port> &ports);
void sendPacket(int portlow, int porthigh, std::string destinationAddress, std::string sourceAddress, bool &isSent);
void sendToOpenPorts(std::string destinationAddress, std::string sourceAddress, bool &isSent, std::vector<openPort> &openPorts);
void recvUDPPacket(std::string sourceAddress, bool &isSent, std::vector<openPort> &openPorts);
void recvFinalPacket(int portlow, int porthigh, std::string sourceAddress, bool &isSent, std::vector<openPort> &ports);
unsigned short checksum(unsigned short *ptr, int nbytes);
std::string getIP();


// COM: Main program.
int main(int argc, char* argv[]) {

    // COM: Check user input arguments.
    if(argc != 4) {
        std::cout << "Usage: ./scanner [destination IP] [port low] [port high] --verbose" << std::endl;
        exit(0);
    }

    std::cout << "Part one: Port scanner ****************************************************************" << std::endl;
    // COM: Part one: Port scanner ****************************************************************
    // COM:
    bool isSent {false};

    // COM: IP addresses and port range.
    std::string sourceAddress(getIP());
    std::string destinationAddress (argv[1]);
    int portLow {atoi(argv[2])};
    int portHigh {atoi(argv[3])};


    // COM: Validating port range.
    if(portLow > portHigh) {
        std::cout << "Enter the lower port before the higher port" << std::endl;
        std::cout << "Usage: ./scanner [source IP] [destination IP] [port low] [port high]" << std::endl;
        exit(0);
    }

    // COM: Datastructure to hold the initial batch of ports.
    std::vector<port> ports;
    // COM: Initialize each port with a portnumber.
    for(int i {portLow}; i <= portHigh; ++i) {
        port initPort;
        initPort.initialize(i);
        ports.push_back(initPort);
    }

    // COM: The first wave of threads. Make first contact. Recieve ICMP.
    std::thread sendThread (sendPacket, portLow, portHigh, destinationAddress, sourceAddress, std::ref(isSent));
    std::thread recvThread (recvPacket, portLow, sourceAddress, std::ref(isSent), std::ref(ports));
    sendThread.join();
    recvThread.join();

    // COM: Reset flag.
    isSent = false;

    // COM: Datastructure to hold the batch of open ports.
    std::vector<openPort> openPorts;
    // COM: Transfer relevant ports to new data structue.
    for(size_t i {0}; i < ports.size(); ++i) {
        if(ports[i].isReceived == false) {
            openPort openPort;
            openPort.initialize(ports[i].portNumber);
            openPorts.push_back(openPort);
        }
    }


    std::cout << "The second wave: Spawn threads. Recieve UDP. Only go if there are any open ports. **********" << std::endl;
    // COM: The second wave: Spawn threads. Recieve UDP. Only go if there are any open ports. **********

    if(openPorts.size() > 0) {
        std::thread sendOpenThread (sendToOpenPorts, destinationAddress, sourceAddress, std::ref(isSent), std::ref(openPorts));
        std::thread recvUDPPacketThread (recvUDPPacket, sourceAddress, std::ref(isSent), std::ref(openPorts));
        sendOpenThread.join();
        recvUDPPacketThread.join();
    }
    else {
        std::cout << "All ports seem to be closed, " + destinationAddress + " maybe down, try again later." << std::endl;
        exit(0);
    }

    std::cout << "The third wave: Deliver and update payload from Evilbit and Checksum. *****************" << std::endl;
    // COM: The third wave: Deliver and update payload from Evilbit and Checksum. *****************

    std::string oraclePayload("");
    int oracleIndex = 0;
    std::string secretPhrase;
    isSent = false;

    // COM: Reset received-flag on data structure.
    for(size_t i {0}; i < openPorts.size(); ++i) {
        openPorts[i].isReceived = false;
    }

    // COM: Now we know the index and location of each port in memory and spin upp the threads for send/receive.
    std::thread sendThread2 (sendToOpenPorts, destinationAddress, sourceAddress, std::ref(isSent), std::ref(openPorts));
    std::thread recvUDPPacketThread2 (recvUDPPacket, sourceAddress, std::ref(isSent), std::ref(openPorts));
    recvUDPPacketThread2.join();
    sendThread2.join();

    std::cout << "The fourth wave: Set up to send correct ports to Oracle. ******************************" << std::endl;
    // COM: The fourth wave: Set up to send correct ports to Oracle. ******************************


    // COM: Iterate through the ports and generate payloads.
    for(size_t i {0}; i < openPorts.size(); ++i) {

        if(openPorts[i].isEvil) {
            // COM: Setting up a RegEx search.
            std::string evil(openPorts[i].message);
            std::smatch match;
            std::regex expression("[0-9]");
            std::string tempStr;
            // COM: Create the new string.
            while(std::regex_search (evil, match, expression)) {
                for(auto x : match) {
                    tempStr.append(x);
                }
                evil = match.suffix().str();
            }
            oraclePayload += tempStr + ",";
        }
        else if (openPorts[i].isPortfwd) {
            oraclePayload += openPorts[i].payload + ",";
        }
        else if (openPorts[i].isChecksum) {
            // COM: Setting up a RegEx search.
            std::string check(openPorts[i].message);
            std::smatch match;
            std::regex expression("\"(.*?)\"");
            std::string tempStr;
            // COM: Create the new string.
            if(std::regex_search (check, match, expression)) {
                tempStr = match.str(1);
            }
            // COM: We have the secret Phrase.
            secretPhrase.append(tempStr);
        }
        else if (openPorts[i].isOracle){
            oracleIndex = i;
        }
    }

    // COM: String manipulation. Data massage.
    oraclePayload.erase(oraclePayload.size() - 1, oraclePayload.size() - 1);

    // COM: Seting up oracle port.
    openPorts[oracleIndex].payload = oraclePayload;
    openPorts[oracleIndex].isLastStand = true;
    openPorts[oracleIndex].isReceived = false;

    // COM: Rest thread flag.
    isSent = false;

    // COM: Generating oracle payload.
    std::thread sendToOracleThread (sendToOpenPorts, destinationAddress, sourceAddress, std::ref(isSent), std::ref(openPorts));
    std::thread recvFromOracleThread (recvUDPPacket, sourceAddress, std::ref(isSent), std::ref(openPorts));
    sendToOracleThread.join();
    recvFromOracleThread.join();

    std::cout << "The fifth wave: Set up & send on correct ports according to the Oracle. ***************" << std::endl;
    // COM: The fifth wave: Set up & send on correct ports according to the Oracle. ***************

    // COM: Data stucture for final message.
    std::vector<openPort> lastMessage;
    // std::cout << "Knock knock rod: " << openPorts[oracleIndex].message << std::endl; // DEBUG:

    // COM: Reading the order of ports to knock on from oracle
    std::string knockKnock(openPorts[oracleIndex].message);
    std::smatch match;
    std::regex expression("[4][0-9][0-9][0-9]");
    std::string tempStr;

    // COM: Iterator initialized. Last match for loop-guard.
    std::sregex_iterator currentMatch(knockKnock.begin(), knockKnock.end(), expression);
    std::sregex_iterator lastMatch;

    // COM: While the current match doesn't equal the last
    while(currentMatch != lastMatch){
        std::smatch match = *currentMatch;
        openPort openPort;
        openPort.initialize(atoi(match.str().c_str()));
        lastMessage.push_back(openPort);
        currentMatch++;
    }

    // COM: Setting up the ports so they go through all logic checks.
    for(size_t i {0}; i < lastMessage.size(); ++i) {
        if(i == lastMessage.size() - 1) {
            lastMessage[i].isReceived = false;
            lastMessage[i].secretPhrase = secretPhrase;
            lastMessage[i].isSecret = true;
            lastMessage[i].isMasterOfTheUniverse = true;
        }
        else {
            lastMessage[i].isReceived = false;
            lastMessage[i].isKnock = true;
            lastMessage[i].secretPhrase = secretPhrase;
        }
    }

    // COM: Reset thread flag.
    isSent = false;

    // COM: Last set of threads going to work.
    std::thread sendLast (sendToOpenPorts, destinationAddress, sourceAddress, std::ref(isSent), std::ref(lastMessage));
    std::thread recvLastUDP (recvUDPPacket, sourceAddress, std::ref(isSent), std::ref(lastMessage));
    std::thread recvLast (recvFinalPacket, portLow, portHigh, sourceAddress, std::ref(isSent), std::ref(lastMessage));
    sendLast.join();
    recvLast.join();
    recvLastUDP.join();

    // for(size_t i {0}; i < lastMessage.size(); ++i) {
    //     if(lastMessage[i].isMasterOfTheUniverse) {
    //         std::cout << "Final message: " << lastMessage[i].message << std::endl; // DEBUG:
    //     }
    // }

    return 0;
}

// COM: The Main receiver function. Accepts ICMP packets.
void recvPacket(int portlow, std::string sourceAddress, bool &isSent, std::vector<port> &ports) {

    int recvSocket {0};
    int received {-1};
    unsigned int received_len {0};
    int bound {0};
    char buffer[1024] {0};

    while (!isSent) {
        // COM: Initializing the socket structure.
        sockaddr_in socketAddress;
        socketAddress.sin_family = AF_INET;
        socketAddress.sin_port = htons(50000);
        inet_pton(AF_INET, sourceAddress.c_str(), &socketAddress.sin_addr);

        // COM: Initializing socket.
        recvSocket = socket(
            AF_INET,
            SOCK_RAW,
            IPPROTO_ICMP
        );

        if(recvSocket < 0){
            std::perror("### Create socket failed");
        }

        // COM: Binding the socket to IP address og port.
        bound = bind(
            recvSocket,
            (struct sockaddr *) &socketAddress,
            sizeof(struct sockaddr_in)
        );

        if(bound < 0){
            std::perror("### Failed to bind");
        }

        // COM: Initializing a timeout period.
        struct timeval timeout;
            timeout.tv_sec = 5;
            timeout.tv_usec = 0;

        // COM: Customizing socket options. Set timeout.
        int setSockOpt = setsockopt(
            recvSocket,
            SOL_SOCKET,
            SO_RCVTIMEO,
            (char *)&timeout,
            sizeof(timeout)
        );

        if(setSockOpt < 0){
            std::perror("### Failed to set sock opt");
        }

        // COM: Atempting to received ICMP packets.
        received = recvfrom(
            recvSocket,
            buffer,
            1024,
            0,
            (struct sockaddr *) &socketAddress,
            &received_len
        );

        // COM: If there is any data recieved, we look at the raw buffer.
        if(received > 0) {

            short * portPtr;
            int currentPort = htons(*portPtr);
            int index = currentPort - portlow;
            unsigned char *ICMPcode;

            // COM: The port number from sender.
            portPtr = (short *)&buffer[50];
            // COM: ICMP code ID.
            ICMPcode = (unsigned char*) &buffer[21];

            // COM: Making the data usable with bit shifting and masking.
            int code = ((htons(*ICMPcode) >> 8) & 0xffff);

            // COM: Toggling the received flag.
            if (code == 3 && !ports[index].isReceived) {
                ports[index].isReceived = true;
                std::cout << "ICMP ID code is " << code << ". " << "Port #" << currentPort << " : Destination Unreachable." << std::endl; // DEBUG:
            }
        }
        // COM: Clearing buffer and recevied data flag.
        memset(buffer, 0, 1024);
        received = -1;
    }

}

void sendPacket(int portlow, int porthigh, std::string destinationAddress, std::string sourceAddress, bool &isSent) {

    int sendSocket {0};
    std::string data = "ping";

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

        if(sendSocket < 0){
            std::perror("### Create UDP_socket failed");
        }

        // COM: Datagram buffer and pointer.
        char datagram[4096] {0};
        char *pseudogram;

        // COM: IP, UDP and Pseudo header structures.
        struct iphdr *iph = (struct iphdr *) datagram;
        struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct iphdr));
        struct pseudo_header psh;

        // COM: Setting data length.
        data = datagram + sizeof(struct iphdr) + sizeof (struct udphdr);

        // COM: Fill in the IP Header.
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr) + strlen(data.c_str());
        iph->id = htonl (54321);
        iph->frag_off = 0;
        iph->ttl = 255;
        iph->protocol = IPPROTO_UDP;
        iph->check = 0;
        iph->saddr = inet_addr (sourceAddress.c_str());
        iph->daddr = socketAddress.sin_addr.s_addr;
        iph->check = checksum ((unsigned short *) datagram, iph->tot_len);

        // COM: UDP header.
        udph->source = htons (50000);
        udph->dest = htons (port);
        udph->len = htons(8 + data.size());
        udph->check = 0;

        // COM: Now the UDP checksum using the pseudo header.
        psh.source_address = inet_addr(sourceAddress.c_str());
        psh.dest_address = socketAddress.sin_addr.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_UDP;
        psh.udp_length = htons(sizeof(struct udphdr) + data.size() );

        // COM: Setting up Pseudoheader for control.
        int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + data.size();
        pseudogram = (char*) malloc(psize);
        memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header) , udph , sizeof(struct udphdr) + data.size());

        // COM: Calculate checksum with Pseudoheader.
        udph->check = checksum((unsigned short*) pseudogram , psize);

        for(int i {0}; i < 5; ++i) {
            sendto(
                sendSocket,
                datagram,
                iph->tot_len,
                MSG_CONFIRM,
                (const struct sockaddr *) &socketAddress,
                sizeof(socketAddress)
            );
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
        free(pseudogram);
    }
    isSent = true;
}

unsigned short checksum(unsigned short *ptr, int bytes) {
    long sum {0};
    unsigned short oddbyte;
    short answer;

    while(bytes > 1) {
        sum += *ptr++;
        bytes -= 2;
    }

    if(bytes == 1) {
        oddbyte = 0;
        *((u_char*) &oddbyte) = *(u_char*) ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short) ~sum;
    return(answer);
}

void sendToOpenPorts(std::string destinationAddress, std::string sourceAddress, bool &isSent, std::vector<openPort> &openPorts) {

    int sendSocket {0};
    char *data;

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

        if(sendSocket < 0){
            std::perror("### Create UDP_socket failed");
        }

        // COM: Socket options included with flag for header.
        int val = 1;
        int sockoption = setsockopt(sendSocket, IPPROTO_IP, IP_HDRINCL, &val, sizeof(val));

        if(sockoption < 0) {
            std::perror("### setsockopt() failed");
            exit(0);
        }

        // COM: Datagram buffer and pointer.
        char datagram[4096] {0};
        char *pseudogram;

        // COM: IP, UDP and Pseudo header structures.
        struct iphdr *iph = (struct iphdr *) datagram;
        struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct iphdr));
        struct pseudo_header psh;

        // COM: Setting data length.
        data = datagram + sizeof(struct iphdr) + sizeof (struct udphdr);

        // COM: Conditional payload assignment.
        if(openPorts[port].isLastStand) {
            strcpy(data, openPorts[port].payload.c_str());
        }
        else if (openPorts[port].isKnock) {
            strcpy(data, openPorts[port].secretPhrase.c_str());
            // std::cout << data; // DEBUG:
            std::cout << "()Knocking on port # " << openPorts[port].portNumber << " index " << port << std::endl; // DEBUG:
        }
        else if (openPorts[port].isSecret) {
            strcpy(data, openPorts[port].secretPhrase.c_str());
            // std::cout << data; // DEBUG:
            std::cout << "()Sending secret to port # " << openPorts[port].portNumber << " index " << port << std::endl; // DEBUG:
        }
        else {
            strcpy(data, "aa");
        }

        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr) + strlen(data);
        iph->id = htonl (54321);
        if(openPorts[port].isEvil) {
            iph->frag_off |= htons(0x8000);
        }
        else {
            iph->frag_off = 0;
        }
        iph->ttl = 255;
        iph->protocol = IPPROTO_UDP;
        iph->check = 0;
        iph->saddr = inet_addr (sourceAddress.c_str());
        iph->daddr = socketAddress.sin_addr.s_addr;

        iph->check = checksum ((unsigned short *) datagram, iph->tot_len);

        udph->source = htons (50000);
        udph->dest = htons (openPorts[port].portNumber);
        udph->len = htons(8 + strlen(data));
        udph->check = 0;

        psh.source_address = inet_addr(sourceAddress.c_str());
        psh.dest_address = socketAddress.sin_addr.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_UDP;
        psh.udp_length = htons(sizeof(struct udphdr) + strlen(data));

        if(openPorts[port].isChecksum) {
            int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr);
            pseudogram = (char*) malloc(psize);

            // COM: Create Pseudo header + UDP header + data structure in memory.
            memcpy(
                pseudogram,
                (char*) &psh,
                sizeof (struct pseudo_header)
            );
            memcpy(
                pseudogram + sizeof(struct pseudo_header),
                udph,
                sizeof(struct udphdr)
            );

            // COM: Calculate the UDP checksum.
            // COM: Get the invert of checksum without the data.
            short checksumUDP = ~(checksum((unsigned short*) pseudogram , psize));

            // COM: Invert of of the value gathered from one of the ports.

            // COM: Dynamic value can be found in openPorts[port].payload but we could not finish adding it because
            // COM: skel.ru.is dropped again. This is difficult to test away from school.
            unsigned short target = 0x0ff2; // HACK:

            // COM: Desired checksum value.
            udph->check = htons(0xf00d);

            // COM: Calculate what the unknown data.
            short d = htons(target) - checksumUDP;

            // COM: The data bytes are set to what need to be so checksum adds up.
            u_char one = d;
            u_char two = (d >> 8);

            // COM: The data then gets injected.
            data[0] = one;
            data[1] = two;
        }
        else {
            // COM: If it's not the checksum businnes there is no need to manipulate checksum.
            int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + strlen(data);
            pseudogram = (char*) malloc(psize);
            memcpy(
                pseudogram,
                (char*) &psh,
                sizeof (struct pseudo_header)
            );
            memcpy(
                pseudogram + sizeof(struct pseudo_header),
                udph,
                sizeof(struct udphdr) + strlen(data)
            );
            udph->check = checksum((unsigned short*) pseudogram , psize);
        }

        for(int i {0}; i < 1; ++i) {
            sendto(
                sendSocket,
                datagram,
                iph->tot_len,
                MSG_CONFIRM,
                (const struct sockaddr *) &socketAddress,
                sizeof(socketAddress)
            );
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
        }
        free(pseudogram);
    }
    isSent = true;
}

void recvUDPPacket(std::string sourceAddress, bool &isSent, std::vector<openPort> &openPorts) {

    int recvSocket {0};
    int received {-1};
    unsigned int received_len {0};
    int bound {0};
    char buffer[1024] {0};
    char *data;

    while (!isSent) {

        sockaddr_in socketAddress;
        socketAddress.sin_family = AF_INET;
        socketAddress.sin_port = htons(50000);
        inet_pton(AF_INET, sourceAddress.c_str(), &socketAddress.sin_addr);

        recvSocket = socket(
            AF_INET,
            SOCK_RAW,
            IPPROTO_UDP
        );

        if(recvSocket < 0){
            std::perror("### Create socket failed");
        }

        bound = bind(
            recvSocket,
            (struct sockaddr *) &socketAddress,
            sizeof(struct sockaddr_in)
        );

        if(bound < 0){
            std::perror("### Failed to bind");
        }


        struct timeval timeout;
            timeout.tv_sec = 2;
            timeout.tv_usec = 0;

        int setSockOpt = setsockopt(
            recvSocket,
            SOL_SOCKET,
            SO_RCVTIMEO,
            (char *)&timeout,
            sizeof(timeout)
        );

        if(setSockOpt < 0){
            std::perror("### Failed to set sock opt");
        }

        received = recvfrom(
            recvSocket,
            buffer,
            1024,
            0,
            (struct sockaddr *) &socketAddress,
            &received_len
        );

        if(received > 0) {

            short * portPtr;
            portPtr = (short *)&buffer[20];
            int sourcePort = htons(*portPtr);

            data = buffer + sizeof(struct iphdr) + sizeof (struct udphdr);

            int index = 0;

            for(size_t i {0}; i < openPorts.size(); ++i) {
                if(openPorts[i].portNumber == sourcePort) {
                    index = i;
                }
            }

            if (openPorts[index].isReceived == false) {
                openPorts[index].isReceived = true;
                openPorts[index].message = data;
                std::cout << "[]Message from port no# " << std::dec << sourcePort << " is: " << std::endl;
                // std::cout << data << std::endl;
            }

            // COM: Here is the logic that figures out who is who and what is what.
            if(!openPorts[index].isEvil && !openPorts[index].isOracle && !openPorts[index].isPortfwd && !openPorts[index].isChecksum && !openPorts[index].isFinalMessage) {

                std::string str1(data), ret;
                std::smatch match2;
                std::regex exp2("[0-9]");
                std::string retStr2;
                while (std::regex_search (str1,match2,exp2)) {
                    for (auto x1:match2) retStr2 += x1;
                    str1 = match2.suffix().str();
                }
                if(retStr2.size() > 0) {
                    if(atoi(retStr2.c_str()) > 4100) {
                        //geri checksum
                        openPorts[index].isChecksum = true;

                        std::cout << "[]Checksum set as true on port #: " << openPorts[index].portNumber << std::endl;
                        // std::cout << retStr2 << std::endl;
                        openPorts[index].payload = retStr2;
                    }
                    else {
                        openPorts[index].isPortfwd = true;
                        openPorts[index].payload = retStr2;
                        std::cout << "[]Portfwd set as true on port #: " << openPorts[index].portNumber << std::endl;
                        // std::cout << str1 << std::endl;
                        // std::cout << "Payload: "<< openPorts[index].payload << std::endl;
                    }
                }
                else {
                    // COM: Check if evil or oracle?
                    std::smatch match;
                    std::regex exp("evil");
                    std::string retStr;
                    while (std::regex_search (str1,match,exp)) {
                        for (auto x1:match) retStr += x1;
                        str1 = match.suffix().str();
                    }
                    if(retStr.size() > 0) { //er evil
                        openPorts[index].isEvil = true;
                        std::cout << "[]Evil set as true on port #: " << openPorts[index].portNumber << std::endl;
                        // std::cout << str1 << std::endl;
                    }
                    else {
                        openPorts[index].isOracle = true;
                        std::cout << "[]Oracle set as true on port #: " << openPorts[index].portNumber << std::endl;
                        // std::cout << str1 << std::endl;
                    }
                }
            }
            else if (!openPorts[index].isFinalMessage ) {
                openPorts[index].message = data;
                std::cout << "[]Message from LATER " << std::dec << sourcePort << " is: " << std::endl;
                // std::cout << data << std::endl;
            }
        }
        memset(buffer, 0, 1024);
        received = -1;
    }
}

// COM: Simple function that asks the system for the host IP. Linux and BSD only.
std::string getIP() {
    std::string ipNumber;
    std::ifstream syscall;
    std::vector<std::string> ipNumbers;
    if(system("hostname -I | cut -d \" \" -f 1 > ddc4960d35d7a58843cdaf6cbec393b9")) {}
    syscall.open("ddc4960d35d7a58843cdaf6cbec393b9");
    while (std::getline(syscall, ipNumber)){
        ipNumbers.push_back(ipNumber);
    }
    syscall.close();
    if(system("rm ddc4960d35d7a58843cdaf6cbec393b9")) {}
    return ipNumbers.at(0);
}

void recvFinalPacket(int portlow, int porthigh, std::string sourceAddress, bool &isSent, std::vector<openPort> &ports) {

    int recvSocket {0};
    int received {-1};
    unsigned int received_len {0};
    int bound {0};
    char buffer[1024] {0};

    while (!isSent) {
        // COM: Initializing the socket structure.
        sockaddr_in socketAddress;
        socketAddress.sin_family = AF_INET;
        socketAddress.sin_port = htons(50000);
        inet_pton(AF_INET, sourceAddress.c_str(), &socketAddress.sin_addr);

        // COM: Initializing socket.
        recvSocket = socket(
            AF_INET,
            SOCK_RAW,
            IPPROTO_ICMP
        );

        if(recvSocket < 0){
            std::perror("### Create socket failed");
        }

        // COM: Binding the socket to IP address og port.
        bound = bind(
            recvSocket,
            (struct sockaddr *) &socketAddress,
            sizeof(struct sockaddr_in)
        );

        if(bound < 0){
            std::perror("### Failed to bind");
        }

        // COM: Initializing a timeout period.
        struct timeval timeout;
            timeout.tv_sec = 5;
            timeout.tv_usec = 0;

        // COM: Customizing socket options. Set timeout.
        int setSockOpt = setsockopt(
            recvSocket,
            SOL_SOCKET,
            SO_RCVTIMEO,
            (char *)&timeout,
            sizeof(timeout)
        );

        if(setSockOpt < 0){
            std::perror("### Failed to set sock opt");
        }

        // COM: Atempting to received ICMP packets.
        received = recvfrom(
            recvSocket,
            buffer,
            1024,
            0,
            (struct sockaddr *) &socketAddress,
            &received_len
        );

        // COM: If there is any data recieved, we look at the raw buffer.
        if(received > 0) {

            char *data{NULL};

            // COM: Setting data length in bytes.
            data = buffer + sizeof(struct iphdr) + sizeof (struct udphdr);

            short * portPtr;
            int currentPort = htons(*portPtr);
            unsigned char *ICMPcode;

            // COM: The port number from sender.
            portPtr = (short *)&buffer[50];
            // COM: ICMP code ID.
            ICMPcode = (unsigned char*) &buffer[21];

            // COM: Making the data usable with bit shifting and masking.
            int code = ((htons(*ICMPcode) >> 8) & 0xffff);

            std::cout << "{}ICMP message code is " << code << ". " << "Port #" << currentPort << " has final message." << std::endl; // DEBUG:
            std::cout << "{}PING message is: " << data << std::endl; // DEBUG:
        }
        // COM: Clearing buffer and recevied data flag.
        memset(buffer, 0, 1024);
        received = -1;
    }

}
