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


// Structures
struct port{
    int portNumber;
    bool isReceived = false;

    // Member function to initialize the datatype (constructor).
    void init (int portNumber) {
        this->portNumber = portNumber;
    }
};

struct openPort{
    int portNumber;
    bool isReceived = false;
    std::string message {0};
    std::string payload {0};
    bool isEvil = false;
    bool isOracle = false;
    bool isPortfwd = false;
    bool isChecksum = false;


    // Public member function to initialize the datatype (constructor).
    void init (int portNumber) {
        this->portNumber = portNumber;
    }
};

// Custom header from the internetz
struct pseudo_header{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t udp_length;
};

// Functions prototypes.
//ATH faerobreytur hugsanlega tharf ekki porthigh
void recvPacket(int portlow, int porthigh, std::string sourceAddress, bool &sendIsDone, std::vector<port> &ports);

void sendPacket(int portlow, int porthigh, std::string destinationAddress, std::string sourceAddress, bool &sendIsDone);

void sendToOpenPorts(std::string destinationAddress, std::string sourceAddress, bool &sendIsDone, std::vector<openPort> &openPorts);

void recvUDPPacket(std::string sourceAddress, bool &sendIsDone, std::vector<openPort> &openPorts);

void printByteArray(int bufferLength, char buffer[]);

unsigned short csum(unsigned short *ptr, int nbytes);

// Main program.
int main(int argc, char* argv[]){

    // Check user input arguments.
    if(argc != 5){
        std::cout << "Usage: ./scanner [source IP] [destination IP] [port low] [port high]" << std::endl;
        exit(0);
    }

    // **********  Port scanner
    bool sendIsDone {false};

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

    std::vector<port> ports;

    for(int i = portLow; i <= portHigh; ++i) {
        port scanPort;
        scanPort.init(i);
        ports.push_back(scanPort);
    }

    std::thread sendThread (sendPacket, portLow, portHigh, destinationAddress, sourceAddress, std::ref(sendIsDone));
    std::thread recvThread (recvPacket, portLow, portHigh, sourceAddress, std::ref(sendIsDone), std::ref(ports));

    sendThread.join();
    recvThread.join();


    /// *********** send to open ports
    sendIsDone = false;

    std::vector<openPort> openPorts;

    for(size_t i = 0; i < ports.size(); ++i) {
        if(ports[i].isReceived == false) {
            openPort openPort;

            openPort.portNumber = ports[i].portNumber;

            openPorts.push_back(openPort);
        }
    }

    for(unsigned int i = 0; i < openPorts.size(); ++i) {
        std::cout << "Open Port is# " << openPorts[i].portNumber << std::endl;
    }

    std::thread sendOpenThread (sendToOpenPorts, destinationAddress, sourceAddress, std::ref(sendIsDone), std::ref(openPorts));
    std::thread recvUDPPacketThread (recvUDPPacket, sourceAddress, std::ref(sendIsDone), std::ref(openPorts));

    sendOpenThread.join();
    recvUDPPacketThread.join();

    return 0;
}


void recvPacket(int portlow, int porthigh, std::string sourceAddress, bool &sendIsDone, std::vector<port> &ports){

    int recvSocket {0};
    int received {-1};
    unsigned int received_len {0};
    int bound {0};
    char buffer[1024] {0};

    while (!sendIsDone) {

        sockaddr_in socketAddress;
        socketAddress.sin_family = AF_INET;
        socketAddress.sin_port = htons(50000);
        inet_pton(AF_INET, sourceAddress.c_str(), &socketAddress.sin_addr);

        recvSocket = socket(
            AF_INET,
            SOCK_RAW,
            IPPROTO_ICMP
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
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;

        int setSockOpt = setsockopt(recvSocket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));

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

        //std::cout << "Response length:  " << received << std::endl;
        //std::cout << "Response: " << std::endl;

        //printByteArray(received, buffer);

        if(received > 0) {

            short * portPtr;

            portPtr = (short *)&buffer[50];

            //std::cout << "PortPtr: " << htons(*portPtr) << std::endl;
            //std::cout << c << std::endl;
            int currentPort = htons(*portPtr);
            int index = currentPort - portlow;

            unsigned char *ICMPcode;

            ICMPcode = (unsigned char*) &buffer[21];

            int code = ((htons(*ICMPcode) >> 8) & 0xffff);

            if (code == 3 && ports[index].isReceived == false) {
                ports[index].isReceived = true;
                std::cout << "ICMP message code is " << code << " therefore" << std::endl;
                std::cout << "Port# " << currentPort << " is closed" << std::endl;
            }
        }

        memset(buffer, 0, 1024);
    }

}


void sendPacket(int portlow, int porthigh, std::string destinationAddress, std::string sourceAddress, bool &sendIsDone){

    int sendSocket {0};
    //int messageDelivered {0};
    std::string data = "ping";

    for(int port {portlow}; port <= porthigh; port++){

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

        //setsockopt
        // int val = 1;
        // int sockoption = setsockopt(sendSocket, IPPROTO_IP, IP_HDRINCL, &val, sizeof(val));

        // if(sockoption < 0) {
        //     perror("setsockopt HDRINCL_IP failed");
        //     exit(0);
        // }

        // ***** create header ****

        //datagram til ad halda utan um pakkann
        char datagram[4096] {0}, *pseudogram;

        //IP og UDP header
        struct iphdr *iph = (struct iphdr *) datagram;

        struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct iphdr));

        //pseudo header buinn til
        struct pseudo_header psh;

        //data sett aftan vid udp header
        data = datagram + sizeof(struct iphdr) + sizeof (struct udphdr);

        //Fill in the IP Header
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr) + strlen(data.c_str());
        iph->id = htonl (54321); //Id of this packet - DOES NOT SEEM TO MATTER WHAT VALUE IS HERE. DYNAMIC???
        iph->frag_off = 0;//htons(0x8000); // EVILBIT GAURINN!!! SENDA SEM BIG-ENDIAN htons() 0x8000 > 0x00 0x80 (|=)
        iph->ttl = 255;
        iph->protocol = IPPROTO_UDP; // WHAT IS THE POINT OF THE SAME THING IN socket() ABOVE?????
        iph->check = 0;      //Set to 0 before calculating checksum
        iph->saddr = inet_addr (sourceAddress.c_str());    //Spoof the source ip address
        iph->daddr = socketAddress.sin_addr.s_addr;

        // IP checksum

        iph->check = csum ((unsigned short *) datagram, iph->tot_len);

        // UDP header
        udph->source = htons (50000);  //nota svarið frá Servernum til að búa til þetta, source portið verður destination port og öfugt
        udph->dest = htons (port);
        udph->len = htons(8 + data.size()); //tcp header size
        udph->check = 0; //leave checksum 0 now, filled later by pseudo header

        // Now the UDP checksum using the pseudo header
        psh.source_address = inet_addr(sourceAddress.c_str());
        psh.dest_address = socketAddress.sin_addr.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_UDP;
        psh.udp_length = htons(sizeof(struct udphdr) + data.size() );

        int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + data.size();

        //muna ad gera free
        pseudogram = (char*) malloc(psize);

        //pusla saman pseudoheader + UDP heade + data
        memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header) , udph , sizeof(struct udphdr) + data.size());

        //Reikna ut UDP checksum
        udph->check = csum((unsigned short*) pseudogram , psize);

        //send message
        for(int i = 0; i < 5; ++i) {
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
    }

    sendIsDone = true;
}

void printByteArray(int bufferLength, char buffer[]){

    for (int i {0}; i < bufferLength; i++) {
        printf("%02X%s", (uint8_t)buffer[i], (i + 1)%16 ? " " : "\n");
    }
    std::cout << std::endl;
}

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
    answer = (short) sum; //taka tilde i burtu til ad fa sum i stad csum

    return(answer);
}

void sendToOpenPorts(std::string destinationAddress, std::string sourceAddress, bool &sendIsDone, std::vector<openPort> &openPorts) {

    int sendSocket {0};
    //int messageDelivered {0};
    char* data;

    for(unsigned int port = 0; port < openPorts.size(); port++){

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


        int val = 1;
        int sockoption = setsockopt(sendSocket, IPPROTO_IP, IP_HDRINCL, &val, sizeof(val));

        if(sockoption < 0) {
            perror("setsockopt HDRINCL_IP failed");
            exit(0);
        }

        // ***** create header ****

        //datagram til ad halda utan um pakkann
        char datagram[4096] {0}, *pseudogram;

        //IP og UDP header
        struct iphdr *iph = (struct iphdr *) datagram;

        struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct iphdr));

        //pseudo header buinn til
        struct pseudo_header psh;

        //data sett aftan vid udp header
        data = datagram + sizeof(struct iphdr) + sizeof (struct udphdr);

        strcpy(data, "aa");

        //Fill in the IP Header
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr) + sizeof(data);
        iph->id = htonl (54321); //Id of this packet - DOES NOT SEEM TO MATTER WHAT VALUE IS HERE. DYNAMIC???
        if(openPorts[port].isEvil) {
            iph->frag_off |= htons(0x8000); // EVILBIT GAURINN!!! SENDA SEM BIG-ENDIAN htons() 0x8000 > 0x00 0x80 (|=)
        }
        else {
            iph->frag_off = 0; // EVILBIT GAURINN!!! SENDA SEM BIG-ENDIAN htons() 0x8000 > 0x00 0x80 (|=)
        }
        iph->ttl = 255;
        iph->protocol = IPPROTO_UDP; // WHAT IS THE POINT OF THE SAME THING IN socket() ABOVE?????
        iph->check = 0;      //Set to 0 before calculating checksum
        iph->saddr = inet_addr (sourceAddress.c_str());    //Spoof the source ip address
        iph->daddr = socketAddress.sin_addr.s_addr;

        // IP checksum
        iph->check = ~(csum ((unsigned short *) datagram, iph->tot_len));


        // UDP header
        udph->source = htons (50000);  //nota svarið frá Servernum til að búa til þetta, source portið verður destination port og öfugt
        udph->dest = htons (openPorts[port].portNumber);
        udph->len = htons(8 + 2); //tcp header size
        udph->check = 0; //leave checksum 0 now, filled later by pseudo header

        // Now the UDP checksum using the pseudo header
        psh.source_address = inet_addr(sourceAddress.c_str());
        psh.dest_address = socketAddress.sin_addr.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_UDP;
        psh.udp_length = htons(sizeof(struct udphdr) + 2); //herna tharf data ad vera 2

        int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr);

        //muna ad gera free
        pseudogram = (char*) malloc(psize);

        //pusla saman pseudoheader + UDP heade + data
        memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header) , udph , sizeof(struct udphdr));

        //Reikna ut UDP checksum
        //if checksum

        short cum = csum((unsigned short*) pseudogram , psize);
        std::cout << "Cumsum ur fallinu: " << std::hex << udph->check << std::endl;
        std::cout << "Cumsum invert ur fallinu: " << std::hex << ~udph->check << std::endl;

        unsigned short target = 0x0ff2;
        std::cout << "CheckNum: " << std::hex << target << std::endl;

        udph->check = htons(0xf00d);

        short d = htons(0x0ff2) - cum;

        std::cout << "dataSum: " << std::hex << d << std::endl;

        //skrifa hardkodad inn i data holfin til ad profa mismunandi gildi
        u_char as = d;
        u_char af = (d >> 8);

        data[0] = as;
        data[1] = af;



        //send message
        for(int i = 0; i < 5; ++i) {
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
    }

    sendIsDone = true;
}

void recvUDPPacket(std::string sourceAddress, bool &sendIsDone, std::vector<openPort> &openPorts) {

    int recvSocket {0};
    int received {-1};
    unsigned int received_len {0};
    int bound {0};
    char buffer[1024] {0};
    char *data;

    while (!sendIsDone) {

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

        int setSockOpt = setsockopt(recvSocket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));

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

            //std::cout << "PortPtr: " << htons(*portPtr) << std::endl;b
            //std::cout << c << std::endl;b
            int sourcePort = htons(*portPtr);

            //convert-a data partinum i streng
            data = buffer + sizeof(struct iphdr) + sizeof (struct udphdr);

            //std::cout << "Source port: " << sourcePort << std::endl;
            //std::cout << "data: " << data << std::endl;

            // finna rett stak i vektornum
            int index;

            for(unsigned int i = 0; i < openPorts.size(); ++i) {
                if(openPorts[i].portNumber == sourcePort) {
                    index = i;
                }
            }

            if (openPorts[index].isReceived == false) {
                openPorts[index].isReceived = true;

                openPorts[index].message = data;
                std::cout << "Message from port# " << sourcePort << " is: " << std::endl;
                std::cout << data << std::endl;
            }

            //Herna finnum vid ut hver er hvad, isEvil, isOracle, isPortMongo, isChecksum
        }

        //printByteArray(sizeof(buffer), buffer);


        memset(buffer, 0, 1024);
    }
}
