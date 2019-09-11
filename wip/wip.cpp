#include <iostream>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

// constexpr int MAXLINES {1024};

// int main(int argc, char *argv[]) {

//     if(argc != 4){
//         std::cout << "Usage: scanner [ip] [low-port] [high-port]" << std::endl;
//         exit(0);
//     }

//     int sockfd {0};
//     int lo_port {0};
//     int hi_port {0};
//     char buffer[MAXLINES];
//     // OK, just fugured out you should not use std::string in conjunction with memset()
//     std::string message = "Hello from client";
//     struct sockaddr_in servaddr;

//     if((sockfd = socket(AF_INET, SOCK_DGRAM, 0))< 0){
//         std::cerr << "socket creation failed" << std::endl;
//         exit(-1);
//     }

//     // If we are not using C strings, but std::string do we need to use this memory allocater?
//     memset(&servaddr, 0, sizeof(servaddr));

//     servaddr.sin_family = AF_INET;
//     servaddr.sin_addr.s_addr = INADDR_ANY;
//     // Here we need to use a whole range of ports
//     // Possibly have a loop feed in the whole range from the input?
//     servaddr.sin_port = htons(5000); // This hard-coded port is NON-SENSE

//     int n {0};
//     unsigned int len {0};

//     sendto(sockfd, message.c_str(), message.size(), MSG_CONFIRM, (const struct sockaddr *) &servaddr, sizeof(servaddr));
//     std::cout << "Hello message sent." << std::endl;


//     // n = recvfrom(sockfd, (char *)buffer, MAXLINES, MSG_WAITALL, (struct sockaddr *) &servaddr, &len);
//     n = recvfrom(sockfd, (char *)buffer, MAXLINES, 0, (struct sockaddr *) &servaddr, &len);
//     buffer[n] = '\0';
//     std::cout << "Server: " << buffer << std::endl;

//     close(sockfd);
//     return 0;
// }


int main(int argc, char *argv[]) {

	std::cout << "The number of arguments is " << argc << std::endl;

    for(int i = 1; i < argc; ++i){
        std::cout << "Argument " << i << " is: " << argv[i] << std::endl;
    }

    return 0;
}



/************* UDP CLIENT CODE *******************/

// #include <stdio.h>
// #include <sys/socket.h>
// #include <netinet/in.h>
// #include <string.h>

// int main(){
//   int clientSocket, portNum, nBytes;
//   char buffer[1024];
//   struct sockaddr_in serverAddr;
//   socklen_t addr_size;

//   /*Create UDP socket*/
//   clientSocket = socket(PF_INET, SOCK_DGRAM, 0);

//   /*Configure settings in address struct*/
//   serverAddr.sin_family = AF_INET;
//   serverAddr.sin_port = htons(7891);
//   serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
//   memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);

//   /*Initialize size variable to be used later on*/
//   addr_size = sizeof serverAddr;

//   while(1){
//     printf("Type a sentence to send to server:\n");
//     fgets(buffer,1024,stdin);
//     printf("You typed: %s",buffer);

//     nBytes = strlen(buffer) + 1;

//     /*Send message to server*/
//     sendto(clientSocket,buffer,nBytes,0,(struct sockaddr *)&serverAddr,addr_size);

//     /*Receive message from server*/
//                 nBytes = recvfrom(clientSocket,buffer,1024,0,NULL, NULL);

//     printf("Received from server: %s\n",buffer);

//   }

//   return 0;
// }