#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <string>
#include <vector>
#include <chrono>
#include <thread>


int main(int argc, char* argv[])
{
    if(argc != 3){
        std::cout << "Usage: client [ip] [portlow]" << std::endl;
        exit(0);
    }

    unsigned short in_cksum(unsigned short *, int);
    int portlow = atoi(argv[2]);
    int sock;
    struct iphdr* ip;
    struct icmphdr* icmp;
    char* packet;
    int optval;

    if (sock < 0) {
        perror("Can't create a socket");
        return -1;
    }

    std::string ipAddress = argv[1]; //ip address to connect to comes from first parameter

    //Create packet
    ip = (struct iphdr*) packet;
    icmp = (struct icmphdr*) (packet + sizeof(struct iphdr));

    std::string myIp = "130.208.240.8";
    //Setja upp ip packet
    ip->ihl = 5;  //length of IP header, min 5, max 6
    ip->version = 4; // IPv4
    ip->tos = 0; //never used
    ip->tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr); //heildarlengdin IP header + user data
    ip->id = htons(0); //??
    ip->frag_off = 0;   //field to fragment and reassemble packets
    ip->ttl = 64; //Time to live
    ip->protocol = IPPROTO_ICMP; //Protocol-id
    ip->saddr = inet_addr(myIp.c_str());  //IP address of sender
    ip->daddr = inet_addr(ipAddress.c_str()); //IP address of destination
    // ip->check = in_cksum((unsigned short *)ip, sizeof(struct iphdr));  //checksum

    /*
    * IP_HDRINCL must be set on the socket so that
    * the kernel does not attempt to automatically add
    * a default ip header to the packet
    */
    sock = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_ICMP);

    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(int));

    //Búa til icmp packet
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = random();
    icmp->un.echo.sequence = 0;
    // icmp-> checksum = in_cksum((unsigned short *)icmp, sizeof(struct icmphdr));

    sockaddr_in sk_addr;
    sk_addr.sin_family = AF_INET;
    sk_addr.sin_port = htons(portlow);
    inet_pton(AF_INET, ipAddress.c_str(), &sk_addr.sin_addr);

    //Senda pakkann
    sendto(sock, packet, ip->tot_len, 0, (const struct sockaddr *) &sk_addr, sizeof(sk_addr));

    close(sock);

    return 0;
}
