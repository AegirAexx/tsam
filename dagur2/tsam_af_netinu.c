#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/time.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <iostream>
#define	DEFDATALEN	(64-ICMP_MINLEN)
#define	MAXIPLEN	60
#define	MAXICMPLEN	76
#define	MAXPACKET	(65536 - 60 - ICMP_MINLEN)

using namespace std;

uint16_t in_cksum(uint16_t *addr, unsigned len);   //Útfært neðst í skránni


int main(int argc, char* argv[])  //ping fall sem tekur inn strenginn target
{
	std::string target = argv[1];
    int s, i, cc, packlen, datalen = DEFDATALEN; //ýmsar int breytur
	struct hostent *hp; //hostent struct, ekki viss afhverju hann er að nota þetta //This structure describes an Internet host
	struct sockaddr_in to, from; //To og from address struct
	struct ip *ip;  //Ip header struct-ið
	u_char *packet, outpack[MAXPACKET]; //pointer sem á væntanlega að benda á pakkann
	char hnamebuf[MAXHOSTNAMELEN]; //char til að geyma hostname
	string hostname; //strengur til að geyma hostname, afhverju bæði char og string?
	struct icmp *icp; //ICMP struct
	int ret, fromlen, hlen;
	fd_set rfds; //file descriptor
	struct timeval tv;  //struct fyrir tímasetningarnar
	int retval; //
	struct timeval start, end;  //2 ný timeval, start og end
	int end_t;
	bool cont = true;

	to.sin_family = AF_INET; //stilla family á To address struct-inu

	to.sin_addr.s_addr = inet_addr(target.c_str());  //stilla address á To struct-inu með target Ip addressunni sem er að koma inn
	if (to.sin_addr.s_addr != (u_int)-1)  //ef það er ekki -1 í s_addr á sockaddr_in To
		hostname = target; //þá er hostname að taka sama gildi og target
	else //Ef sockaddr_in.s_addr == -1
	{
		hp = gethostbyname(target.c_str());  //Hérna er ég held ég að ná í upplýsingar um hostinn og geyma í þessu hp struct-i, er ég að ná í upplýsingar um sjálfan mig hér?
		if (!hp) //error check væntanlega ef ekki finnst host
		{
			cerr << "unknown host "<< target << endl;
			return -1;
		}
		to.sin_family = hp->h_addrtype; //hérna er ég þá að fylla út í restina af þessu struct-i
		bcopy(hp->h_addr, (caddr_t)&to.sin_addr, hp->h_length); //
		strncpy(hnamebuf, hp->h_name, sizeof(hnamebuf) - 1); //
		hostname = hnamebuf; //hér er þá væntanlega IP addressan
	}

	packlen = datalen + MAXIPLEN + MAXICMPLEN; //Heildarstærðin á pakkanum er jafnt og data + IPheader + ICMPheader
	if ( (packet = (u_char *)malloc((u_int)packlen)) == NULL)  //taka frá minni fyrir þessu
	{
		cerr << "malloc error\n";
		return -1;
	}


	if ( (s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)  //búa til socket af raw tegund sem tekur við ICMP protocol-i
	{
		return -1; /* Needs to run as superuser!! */
	}

	icp = (struct icmp *)outpack; //struct sem heldur utan um pakkann sem ég ætla að senda
	icp->icmp_type = ICMP_ECHO; //Fylla út í öll gildin í icp struct-inu
	icp->icmp_code = 0;
	icp->icmp_cksum = 0;
	icp->icmp_seq = 12345;
	icp->icmp_id = getpid();  //hvaða fall er verið að kalla á þarna


	cc = datalen + ICMP_MINLEN;  //veit ekki alveg hvað cc gerir hér, væntanlega lengdin á pakkanum
	icp->icmp_cksum = in_cksum((unsigned short *)icp,cc);  //reikna út ip checksum

	gettimeofday(&start, NULL); //ná í tíma dags?? veit ekki alveg afhverju

	//Hérna kemur svo send fallið sem tekur inn char pointer á heildarpakkann og struct addressuna To
	i = sendto(s, (char *)outpack, cc, 0, (struct sockaddr*)&to, (socklen_t)sizeof(struct sockaddr_in));
	if (i < 0 || i != cc) //error check
	{
		if (i < 0)
			perror("sendto error");
		cout << "wrote " << hostname << " " <<  cc << " chars, ret= " << i << endl;
	}

	FD_ZERO(&rfds); //hérna eru einhverjir file descriptorar settir, skil ekki alveg
	FD_SET(s, &rfds);
	tv.tv_sec = 1;  //tími settur á timeval struct-ið frá því áðan
	tv.tv_usec = 0;

	while(cont)
	{
		retval = select(s+1, &rfds, NULL, NULL, &tv); //hvað er hann að gera hérna með select á retval
		//select() and pselect() allow a program to monitor multiple file descriptors,
		// waiting until one or more of the file descriptors become "ready" for some class of I/O operation
		if (retval == -1)
		{
			perror("select()");
			return -1;
		}
		else if (retval) //ef að socket-ið er ready þá kalla ég á receive from, spurning hvort ég þurfi nokkuð þetta ef ég er með setsockopt
		{
			fromlen = sizeof(sockaddr_in);
			//hérna er ég að setja upp stillingar á recvfrom socket-inu
			//sendi inn socket-ið (sama og áðan), buffer sem grípur pakkann, lengdin á pakkanum, From struct-ið, lengdin á því structi
			if ( (ret = recvfrom(s, (char *)packet, packlen, 0,(struct sockaddr *)&from, (socklen_t*)&fromlen)) < 0)
			{
				perror("recvfrom error");
				return -1;
			}

			// Check the IP header
			ip = (struct ip *)((char*)packet); //læt ip pointerinn benda á byrjunina á buffernum
			hlen = sizeof( struct ip ); //stærðin á headernum er stærðin á ip
			if (ret < (hlen + ICMP_MINLEN))  //error check
			{
				cerr << "packet too short (" << ret  << " bytes) from " << hostname << endl;;
				return -1;
			}

			// Now the ICMP part
			icp = (struct icmp *)(packet + hlen); //hér læt ég icp struct-ið benda á staðinn þar sem header-inn endar

			if (icp->icmp_type == ICMP_ECHOREPLY)  //hérna er ég að skoða hvernig týpu af skilaboðum ég fékk, ef ég fékk echo reply þá skrifa ég út
			{
				if (icp->icmp_seq != 12345) //hvað er þetta? //The user on the source host can set this optional value to match sent echo requests with received replies
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
			else  //annars, skrifa ég út að ég fékk ekkert reply
			{
				cout << "Recv: not an echo reply" << endl;
				continue;
			}

			gettimeofday(&end, NULL);  //time of day virðist vera bara til að hjálpa mér að mæla hvað ég er lengi að þessu
			end_t = 1000000*(end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec);

			if(end_t < 1)
				end_t = 1;

			cout << "Elapsed time = " << end_t << " usec" << endl;
			return end_t;
		}
		else
		{
			cout << "No data within one seconds.\n";
			return 0;
		}
	}
	return 0;
}

uint16_t in_cksum(uint16_t *addr, unsigned len)  //hérna kemur checksum fallið að ofan
{
  uint16_t answer = 0; //bý til 16 bita tölu hér
  /*
   * Algorithm is simple, using a 32 bit accumulator (sum), add
   * sequential 16 bit words to it, and at the end, fold back all the
   * carry bits from the t   16 bits into the lower 16 bits.
   */
  uint32_t sum = 0; //bý til 32 bita tölu hér
  while (len > 1)  { //á meðan að lengdin á len er meiri en einn þá ætla ég að
    sum += *addr++; //lesa úr pakkanum, bæta staki 2 í sum töluna
    len -= 2; //mínusa svo um 2 og keyr aftur
  }
	//ef ég skil þetta rétt þá er verið að taka annaðhvert stak úr buffernum og setja í sum

  if (len == 1) { //ef að lengdin er komin niður í einn þá
    *(unsigned char *)&answer = *(unsigned char *)addr ; //set ég það sem er í buffernum í answer breytuna
    sum += answer; //bæti henni svo við sum breytuna
  }

  sum = (sum >> 16) + (sum & 0xffff);  //sum er þá shiftað 16 bita og svo and-að á móti 0xffff sem fyllir þá einn í öll fremstu? stökin held ég
  sum += (sum >> 16); //og svo bæti ég þessu við sum
  answer = ~sum; //hvað þýðir tilde merkið hér!!! wtf!
  return answer; //svo skila ég svarinu
}