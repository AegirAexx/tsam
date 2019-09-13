// Copyleft - dagur17@ru.is - aegir15@ru.is - Reykjavik University - 2019.
// UDP port scanner for T-409-TSAM Assignment 3 / Project 2

// Tips from Petur
// getsockname() is part of the bind() shit

// CHECKSUM
// pshdr + udphdr + data = (0x0FF2) > inverted > (CSUM) 0xF00D(61453)
// pshdr + udphdr - 0x0FF2 = data

// Compile flag for threading
// -pthread

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

// Custom header from the internetz
struct pseudo_header{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t udp_length;
};

// Datatype to keep valid ports.
struct openPort{
    int port_no;
    std::string message;

    // Public member function to initialize the datatype (constructor).
    void init (int port, std::string message) {
        this->port_no = port;
        this->message = message;
    }
};

// Function that prints out hex values.
void packet_dump(char *buf, const unsigned int len){
    unsigned char c;
    int i, j;
    for(i = 0; i < len; i++) {
        printf("%02x ", buf[i]);
        if((i % 16) == 15 || (i == len - 1)) {
            for(j = 0; j < 15 - (i % 16); j++) printf("   ");
            printf("| ");
            for(j = (i - (i % 16)); j <= i; j++) {
                c = buf[j];
                if((c > 31) && (c < 127))
                    printf("%c", c);
                else
                    printf(".");
            }
            printf("\n");
        }
    }
}

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

    // Check user input
    if(argc != 4){
        std::cout << "Usage: client [ip] [portlow] [porthigh]" << std::endl;
        exit(0);
    }

    // User input
    int portlow = atoi(argv[2]);
    int porthigh = atoi(argv[3]);

    if(portlow > porthigh) {
        std::cout << "Enter low port before high port" << std::endl;
        std::cout << "Usage: client [ip] [portlow] [porthigh]" << std::endl;
        exit(0);
    }

    // Data structure to keep the open ports found.
    std::vector<openPort> openPorts;

    // Message sent to server.
    std::string message = "knock";

    // Create two sockets - UDP and ICMP.
    int UDP_sock;
    int ICMP_sock;
    // int sendSock;

    //ip address to connect to comes from first parameter.
    std::string ipAddress = argv[1];

    // hostname -I
    std::string sourceAddress = "10.3.17.142";

    // Two buffers for responses.
    char UDPResponse[1024];
    char ICMPResponse[1024];

    // Two int's for return codes.
    int UDP_received;
    int ICMP_received;

    // Main loop that acts on each port in the range given.
    for(int i = portlow; i <= porthigh; i++){

        // Assign two sockets - UDP and ICMP
        // DO WE NEED ALL THESE SOCKETS???
        // DOES NOT NEED TO HAVE NON_BLOCK???
        // PETUR OG THROSTUR DO NOT HAVE THE IPPROTO_RAW SOCKET.

        // sendSock = socket (AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_RAW);
        UDP_sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
        ICMP_sock = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_ICMP);

        if (UDP_sock < 0) {
            perror("Can't create a socket");
            return -1;
        }

        if (ICMP_sock < 0) {
            perror("Can't create a recv socket");
            return -1;
        }

        // if (sendSock < 0) {
        //     perror("Can't create a socket");
        //     return -1;
        // }

        // DEBUG - REMOVE
        // std::cout << "checking port: " << i << std::endl;
        // --------------


        // MAYBE CHANGE TO STD::FILL ??? MEMORY LEAKS
        // DO WE NEED TWO BUFFERS???
        memset(UDPResponse, 0, 1024);
        memset(ICMPResponse, 0, 1024);

        // Socket address struct
        sockaddr_in sk_addr;
        sk_addr.sin_family = AF_INET;
        sk_addr.sin_port = htons(i);
        inet_pton(AF_INET, ipAddress.c_str(), &sk_addr.sin_addr);

        // Set the return codes to -1 on each loop to be able to moniter changes.
        UDP_received = -1;
        ICMP_received = -1;

        // DEBUG - REMOVE
        // std::cout << "UDP x: " << UDP_received << std::endl;
        // std::cout << "ICMP x: " << ICMP_received << std::endl;
        // --------------

        // ----------------------------
        // Create our own IP header
        // ----------------------------

        // TAKE THIS OUT OF THE FOR LOOP????
        //Datagram to represent the packet
        char datagram[4096] , *data , *pseudogram;

        //zero out the packet buffer
        memset(datagram, 0, 4096);

        //IP header
        struct iphdr *iph = (struct iphdr *) datagram;

        //UDP header - (struct ip?)
        struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct iphdr));

        //Pseudo header afhverju?
        struct pseudo_header psh;

        //data part
        data = datagram + sizeof(struct iphdr) + sizeof (struct udphdr);

        // C++ EQUIVALENT?????
        // THERE IS ALSO A STD::STRING AT THE TOP!!
        strcpy(data , "knock");

        //Fill in the IP Header
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr) + strlen(data);
        iph->id = htonl (54321); //Id of this packet
        iph->frag_off = 0; // EVILBIT GAURINN!!! SENDA SEM BIG-ENDIAN htons() 0x8000 > 0x00 0x80 (|=)
        iph->ttl = 255;
        iph->protocol = IPPROTO_UDP; // WHAT IS THE POINT OF THE SAME THING IN socket() ABOVE?????
        iph->check = 0;      //Set to 0 before calculating checksum
        iph->saddr = inet_addr (sourceAddress.c_str());    //Spoof the source ip address
        iph->daddr = sk_addr.sin_addr.s_addr;

        // IP checksum
        // TIPS FROM THE GUYS ABOVE!!!!
        iph->check = csum ((unsigned short *) datagram, iph->tot_len);

        // UDP header
        udph->source = htons (sk_addr.sin_port);  //nota svarið frá Servernum til að búa til þetta, source portið verður destination port og öfugt
        udph->dest = htons (i);
        udph->len = htons(8 + strlen(data)); //tcp header size
        udph->check = 0; //leave checksum 0 now, filled later by pseudo header

        // Now the UDP checksum using the pseudo header
        psh.source_address = inet_addr(sourceAddress.c_str());
        psh.dest_address = sk_addr.sin_addr.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_UDP;
        psh.udp_length = htons(sizeof(struct udphdr) + strlen(data) );

        // CALCULATE TOTAL SIZE OF HEADER
        int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + strlen(data);

        //--------
        // MISSING FREE(DELETE)?????
        // -------
        //malloc a pseudogram
        pseudogram = (char*) malloc(psize);

        //pusla saman pseudoheader + UDP heade + data
        memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header) , udph , sizeof(struct udphdr) + strlen(data));

        //Reikna ut UDP checksum
        udph->check = csum((unsigned short*) pseudogram , psize);

        // Loop to "knock" on the port.
        while(UDP_received == -1 && ICMP_received == -1) {

            // TODO: This does not have to be a variable? Does it?
            int send = sendto(UDP_sock, datagram, iph->tot_len, 0, (const struct sockaddr *) &sk_addr, sizeof(sk_addr));

            // DEBUG - REMOVE
            std::cout << "--------------------------" << std::endl;
            std::cout << "Knocking on port#: " << i << std::endl;
            // --------------

            // Listen for the response - Either UPD or ICMP.
            UDP_received = recvfrom(UDP_sock, UDPResponse, 1024, 0, NULL,  NULL);
            ICMP_received = recvfrom(ICMP_sock, ICMPResponse, 1024, 0, NULL,  NULL);

            // Have the client wait 500ms between knocks.
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }

        // DEBUG - REMOVE
        std::cout << "--------------------------" << std::endl;
        std::cout << "-------LENGTH-------------" << std::endl;
        std::cout << "UDP: " << UDP_received << std::endl;
        std::cout << "ICMP: " << ICMP_received << std::endl;
        std::cout << "--------------------------" << std::endl;
        // --------------

        // If there is there has been an UDP answer from the server, push it to the custom datatype to the data structure.
        if(UDP_received != -1) {
            // Allocate datatype
            openPort port;
            // C_string => std::string.
            std::string res(UDPResponse);
            // Inititialize datatype (constructor).
            port.init(i, res);
            // Push the port info to data stucture.
            openPorts.push_back(port);
            // DEBUG - REMOVE
            std::cout << "pushing port to vector: " << i << std::endl;
            // --------------
        }
        std::cout << "---------ICMP-------------" << std::endl;
        std::cout << "--------------------------" << std::endl;
        std::cout << "------BYTE ARRAY----------" << std::endl;

        struct ip *ip_hdr;
        ip_hdr = (struct ip *)ICMPResponse;

        for (int j = 0; j < ICMP_received; j++) {
            printf("%02X%s", (uint8_t)ICMPResponse[j], (j + 1)%16 ? " " : "\n");
        }
        printf("\n");

        std::cout << "-------PACKET DUMP---------" << std::endl;

        if(ICMP_received != -1) {
            packet_dump(ICMPResponse, ICMP_received);
        }

        struct icmp *icmp = (struct icmp *)(ICMPResponse + sizeof(ip_hdr));
        std::cout << "--------------------------" << std::endl;
        std::cout << std::endl;
        std::cout << std::endl;

        /*
        // Check the IP header
        ip = (struct ip *)((char*)packet);
        hlen = sizeof( struct ip );
        if (ret < (hlen + ICMP_MINLEN))
        {
            cerr << "packet too short (" << ret  << " bytes) from " << hostname << endl;;
            return -1;
        }

        // Now the ICMP part
        icp = (struct icmp *)(packet + hlen);
        if (icp->icmp_type == ICMP_ECHOREPLY)
        {
            if (icp->icmp_seq != 12345)
            {
                cout << "received sequence # " << icp->icmp_seq << endl;
                continue;
            }
            if (icp->icmp_id != getpid())
            {
                cout << "received id " << icp->icmp_id << endl;
                continue;
            }
            cont = false;
        }
        else
        {
            cout << "Recv: not an echo reply" << endl;
            continue;
        }

        */

        // Close the sockets
        close(UDP_sock);
        close(ICMP_sock);
    }

    //Prenta út ICMP skilaboðin

    //Prófa svo að senda svar


    // WIP - WIP - WIP - WIP
    std::cout << std::endl;
    std::cout << std::endl;

    for(size_t i = 0; i < openPorts.size(); ++i) {
        std::cout << "OPEN PORTS: " << openPorts[i].port_no <<  " message: " << openPorts[i].message << std::endl;
    }

    return 0;
}
