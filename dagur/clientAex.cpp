// Copyleft - dagur17@ru.is - aegir15@ru.is - Reykjavik University - 2019.
// UDP port scanner for T-409-TSAM Assignment 3 / Project 2

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

// Datatype to keep valid ports.
struct openPort {
    int port_no;
    std::string message;

    // Public member function to initialize the datatype (constructor).
    void init (int port, std::string message) {
        this->port_no = port;
        this->message = message;
    }
};

// 
void packet_dump(char *buf, const unsigned int len)
{
        unsigned char c;
        int i,j;
        for(i = 0; i < len; i++) {
                printf("%02x ", buf[i]);
                if((i % 16) == 15 || (i == len-1)) {
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


int main(int argc, char* argv[])
{

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

    // ----------------------------------------------------------------------
    // What is this??
    if (UDP_sock < 0) {
        perror("Can't create a socket");
        return -1;
    }

    if (ICMP_sock < 0) {
        perror("Can't create a recv socket");
        return -1;
    }
    // ----------------------------------------------------------------------

    //ip address to connect to comes from first parameter.
    std::string ipAddress = argv[1];

    // Two buffers for responses.
    char UDPResponse[1024];
    char ICMPResponse[1024];

    // Two int's for return codes.
    int UDP_received;
    int ICMP_received;

    // Main loop that acts on each port in the range given.
    for(int i = portlow; i <= porthigh; i++){

        // Assign two sockets - UDP and ICMP
        UDP_sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
        ICMP_sock = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK , IPPROTO_ICMP);

        // DEBUG - REMOVE
        std::cout << "checking port: " << i << std::endl;
        // --------------


        // MAYBE CHANGE TO STD::FILL ??? MEMORY LEAKS
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
        std::cout << "UDP x: " << UDP_received << std::endl;
        std::cout << "ICMP x: " << ICMP_received << std::endl;
        // --------------

        // Loop to "knock" on the port.
        while(ICMP_received == -1) {

            // TODO: This does not have to be a variable? Does it?
            int send = sendto(UDP_sock, message.c_str(), message.size(), MSG_CONFIRM, (const struct sockaddr *) &sk_addr, sizeof(sk_addr));

            // DEBUG - REMOVE
            std::cout << "Sending knock to port: " << i << std::endl;
            // --------------

            // Listen for the response - Either UPD or ICMP.
            UDP_received = recvfrom(UDP_sock, UDPResponse, 1024, 0, NULL,  NULL);
            ICMP_received = recvfrom(ICMP_sock, ICMPResponse, 1024, 0, NULL,  NULL);

            // Have the client wait 500ms between knocks.
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }

        // DEBUG - REMOVE
        std::cout << "UDP: " << UDP_received << std::endl;
        std::cout << "ICMP: " << ICMP_received << std::endl;
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
            std::cout << "pushing port: " << i << std::endl;
            // --------------
        }

        struct ip *ip_hdr;
        ip_hdr = (struct ip *)ICMPResponse;

        for (int j = 0; j < ICMP_received; j++) {
        printf("%02X%s", (uint8_t)ICMPResponse[j], (j + 1)%16 ? " " : "\n");
        }
        printf("\n");

        packet_dump(ICMPResponse, ICMP_received);

        struct icmp *icmp = (struct icmp *)(ICMPResponse + sizeof(ip_hdr));


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

    for(size_t i = 0; i < openPorts.size(); ++i) {
        std::cout << "OPEN PORTS: " << openPorts[i].port_no <<  " message: " << openPorts[i].message << std::endl;
    }

    return 0;
}
