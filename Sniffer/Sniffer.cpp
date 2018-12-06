#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <stdio.h>
#include <WinSock2.h>

#pragma comment(lib,"ws2_32.lib") //For winsock

#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1) //this removes the need of mstcpip.h

void StartSniffing(SOCKET Sock); //This will sniff here and there

void ProcessPacket(char*, int); //This will decide how to digest
void PrintIpHeader(char*, FILE*);
void PrintIcmpPacket(char*, int);
// void PrintIgmpPacket(char*, int);
void PrintUdpPacket(char*, int);
void PrintTcpPacket(char*, int);
// void ConvertToHex(char*, unsigned int);
void PrintData(char*, int, FILE*);

typedef struct ip_hdr
{
	unsigned char ip_header_len : 4; // 4-bit header length (in 32-bit words) normally=5 (Means 20 Bytes may be 24 also)
	unsigned char ip_version : 4; // 4-bit IPv4 version
	unsigned char ip_tos; // IP type of service
	unsigned short ip_total_length; // Total length
	unsigned short ip_id; // Unique identifier

	unsigned char ip_frag_offset : 5; // Fragment offset field

	unsigned char ip_more_fragment : 1;
	unsigned char ip_dont_fragment : 1;
	unsigned char ip_reserved_zero : 1;

	unsigned char ip_frag_offset1; //fragment offset

	unsigned char ip_ttl; // Time to live
	unsigned char ip_protocol; // Protocol(TCP,UDP etc)
	unsigned short ip_checksum; // IP checksum
	unsigned int ip_srcaddr; // Source address
	unsigned int ip_destaddr; // Source address
} IPV4_HDR;

typedef struct udp_hdr
{
	unsigned short source_port; // Source port no.
	unsigned short dest_port; // Dest. port no.
	unsigned short udp_length; // Udp packet length
	unsigned short udp_checksum; // Udp checksum (optional)
} UDP_HDR;

// TCP header
typedef struct tcp_header
{
	unsigned short source_port; // source port
	unsigned short dest_port; // destination port
	unsigned int sequence; // sequence number - 32 bits
	unsigned int acknowledge; // acknowledgement number - 32 bits

	unsigned char ns : 1; //Nonce Sum Flag Added in RFC 3540.
	unsigned char reserved_part1 : 3; //according to rfc
	unsigned char data_offset : 4; /*The number of 32-bit words in the TCP header.
								   This indicates where the data begins.
								   The length of the TCP header is always a multiple
								   of 32 bits.*/

	unsigned char fin : 1; //Finish Flag
	unsigned char syn : 1; //Synchronise Flag
	unsigned char rst : 1; //Reset Flag
	unsigned char psh : 1; //Push Flag
	unsigned char ack : 1; //Acknowledgement Flag
	unsigned char urg : 1; //Urgent Flag

	unsigned char ecn : 1; //ECN-Echo Flag
	unsigned char cwr : 1; //Congestion Window Reduced Flag

						   ////////////////////////////////

	unsigned short window; // window
	unsigned short checksum; // checksum
	unsigned short urgent_pointer; // urgent pointer
} TCP_HDR;

typedef struct icmp_hdr
{
	BYTE type; // ICMP Error type
	BYTE code; // Type sub code
	USHORT checksum;
	USHORT id;
	USHORT seq;
} ICMP_HDR;

FILE *UDP_ETC_logfile;
FILE *UDP_HTTP_logfile;
FILE *UDP_HTTPS_logfile;
FILE *UDP_SMTP_logfile;
FILE *UDP_FTP_logfile;
FILE *UDP_DNS_logfile;

FILE *TCP_ETC_logfile;
FILE *TCP_HTTP_logfile;
FILE *TCP_HTTPS_logfile;
FILE *TCP_SMTP_logfile;
FILE *TCP_FTP_logfile;
FILE *TCP_DNS_logfile;

FILE *OTHER_logfile;

int tcp_etc = 0, tcp_http = 0, tcp_https = 0, tcp_smtp = 0, tcp_ftp = 0, tcp_dns = 0;
int udp_etc = 0, udp_http = 0, udp_https = 0, udp_smtp = 0, udp_ftp = 0, udp_dns = 0;
int icmp = 0, others = 0, igmp = 0, total = 0, i, j;
struct sockaddr_in source, dest;
char hex[2];

//Its free!
IPV4_HDR *iphdr;
TCP_HDR *tcpheader;
UDP_HDR *udpheader;
ICMP_HDR *icmpheader;

int main()
{
	SOCKET sniffer;
	struct in_addr addr;
	int in;

	char hostname[100];
	struct hostent *local;
	WSADATA wsa;

	UDP_ETC_logfile = fopen("UDP_ETC_log.txt", "w");
	if (UDP_ETC_logfile == NULL) printf("Unable to create file.");
	UDP_HTTP_logfile = fopen("UDP_HTTP_log.txt", "w");
	if (UDP_HTTP_logfile == NULL) printf("Unable to create file.");
	UDP_HTTPS_logfile = fopen("UDP_HTTPS_log.txt", "w");
	if (UDP_HTTPS_logfile == NULL) printf("Unable to create file.");
	UDP_SMTP_logfile = fopen("UDP_SMTP_log.txt", "w");
	if (UDP_SMTP_logfile == NULL) printf("Unable to create file.");
	UDP_FTP_logfile = fopen("UDP_FTP_log.txt", "w");
	if (UDP_FTP_logfile == NULL) printf("Unable to create file.");
	UDP_DNS_logfile = fopen("UDP_DNS_log.txt", "w");
	if (UDP_DNS_logfile == NULL) printf("Unable to create file.");
	
	TCP_ETC_logfile = fopen("TCP_ETC_log.txt", "w");
	if (TCP_ETC_logfile == NULL) printf("Unable to create file.");
	TCP_HTTP_logfile = fopen("TCP_HTTP_log.txt", "w");
	if (TCP_HTTP_logfile == NULL) printf("Unable to create file.");
	TCP_HTTPS_logfile = fopen("TCP_HTTPS_log.txt", "w");
	if (TCP_HTTPS_logfile == NULL) printf("Unable to create file.");
	TCP_SMTP_logfile = fopen("TCP_SMTP_log.txt", "w");
	if (TCP_SMTP_logfile == NULL) printf("Unable to create file.");
	TCP_FTP_logfile = fopen("TCP_FTP_log.txt", "w");
	if (TCP_FTP_logfile == NULL) printf("Unable to create file.");
	TCP_DNS_logfile = fopen("TCP_DNS_log.txt", "w");
	if (TCP_DNS_logfile == NULL) printf("Unable to create file.");

	OTHER_logfile = fopen("Other_log.txt", "w");
	if (OTHER_logfile == NULL) printf("Unable to create file.");

	//Initialise Winsock
	printf("\nInitialising Winsock...");
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		printf("WSAStartup() failed.\n");
		return 1;
	}
	printf("Initialised");

	//Create a RAW Socket
	printf("\nCreating RAW Socket...");
	sniffer = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	if (sniffer == INVALID_SOCKET)
	{
		printf("Failed to create raw socket.\n");
		return 1;
	}
	printf("Created.");

	//Retrive the local hostname
	if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR)
	{
		printf("Error : %d", WSAGetLastError());
		return 1;
	}
	printf("\nHost name : %s \n", hostname);

	//Retrive the available IPs of the local host
	local = gethostbyname(hostname);
	printf("\nAvailable Network Interfaces : \n");
	if (local == NULL)
	{
		printf("Error : %d.\n", WSAGetLastError());
		return 1;
	}

	for (i = 0; local->h_addr_list[i] != 0; ++i)
	{
		memcpy(&addr, local->h_addr_list[i], sizeof(struct in_addr));
		printf("Interface Number : %d Address : %s\n", i, inet_ntoa(addr));
	}

	printf("Enter the interface number you would like to sniff : ");
	scanf("%d", &in);

	memset(&dest, 0, sizeof(dest));
	memcpy(&dest.sin_addr.s_addr, local->h_addr_list[in], sizeof(dest.sin_addr.s_addr));
	dest.sin_family = AF_INET;
	dest.sin_port = 0;

	printf("\nBinding socket to local system and port 0 ...");
	if (bind(sniffer, (struct sockaddr *)&dest, sizeof(dest)) == SOCKET_ERROR)
	{
		printf("bind(%s) failed.\n", inet_ntoa(addr));
		return 1;
	}
	printf("Binding successful");

	//Enable this socket with the power to sniff : SIO_RCVALL is the key Receive ALL ;)

	j = 1;
	printf("\nSetting socket to sniff...");
	if (WSAIoctl(sniffer, SIO_RCVALL, &j, sizeof(j), 0, 0, (LPDWORD)&in, 0, 0) == SOCKET_ERROR)
	{
		printf("WSAIoctl() failed.\n");
		return 1;
	}
	printf("Socket set.");

	//Begin
	printf("\nStarted Sniffing\n");
	printf("Packet Capture Statistics...\n");
	
	system("cls");
	
	StartSniffing(sniffer); //Happy Sniffing

							//End
	closesocket(sniffer);
	WSACleanup();

	return 0;
}

void StartSniffing(SOCKET sniffer)
{
	char *Buffer = (char *)malloc(65536); //Its Big!
	int mangobyte;

	if (Buffer == NULL)
	{
		printf("malloc() failed.\n");
		return;
	}

	do
	{
		mangobyte = recvfrom(sniffer, Buffer, 65536, 0, 0, 0); //Eat as much as u can

		if (mangobyte > 0)
		{
			ProcessPacket(Buffer, mangobyte);
		}
		else
		{
			printf("recvfrom() failed.\n");
		}
	} while (mangobyte > 0);

	free(Buffer);
}

void ProcessPacket(char* Buffer, int Size)
{
	iphdr = (IPV4_HDR *)Buffer;
	++total;
	switch (iphdr->ip_protocol) //Check the Protocol and do accordingly...
	{
	case 1: //ICMP Protocol
		++icmp;
		PrintIcmpPacket(Buffer, Size);
		break;

	case 2: //IGMP Protocol
		++igmp;
		break;

	case 6: //TCP Protocol
		PrintTcpPacket(Buffer, Size);
		break;

	case 17: //UDP Protocol
		PrintUdpPacket(Buffer, Size);
		break;

	default: //Some Other Protocol like ARP etc.
		++others;
		break;
	}
	SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), {0, 0});
	printf("TCP_ETC : %d\tTCP_FTP : %d\tTCP_SMTP : %d\tTCP_DNS : %d\tTCP_HTTP : %d\tTCP_HTTPS : %d\n", tcp_etc, tcp_ftp, tcp_smtp, tcp_dns, tcp_http, tcp_https);
	printf("UDP_ETC : %d\tUDP_FTP : %d\tUDP_SMTP : %d\tUDP_DNS : %d\tUDP_HTTP : %d\tUDP_HTTPS : %d\n", udp_etc, udp_ftp, udp_smtp, udp_dns, udp_http, udp_https);
	printf("ICMP : %d\tIGMP : %d\tOthers : %d\tTotal : %d\n", icmp, igmp, others, total);
}

void PrintIpHeader(char* Buffer, FILE* p_file)
{
	unsigned short iphdrlen;

	iphdr = (IPV4_HDR *)Buffer;
	iphdrlen = iphdr->ip_header_len * 4;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iphdr->ip_srcaddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iphdr->ip_destaddr;

	fprintf(p_file, "\n");
	fprintf(p_file, "IP Header\n");
	fprintf(p_file, " |-IP Version : %d\n", (unsigned int)iphdr->ip_version);
	fprintf(p_file, " |-IP Header Length : %d DWORDS or %d Bytes\n", (unsigned int)iphdr->ip_header_len, ((unsigned int)(iphdr->ip_header_len)) * 4);
	fprintf(p_file, " |-Type Of Service : %d\n", (unsigned int)iphdr->ip_tos);
	fprintf(p_file, " |-IP Total Length : %d Bytes(Size of Packet)\n", ntohs(iphdr->ip_total_length));
	fprintf(p_file, " |-Identification : %d\n", ntohs(iphdr->ip_id));
	fprintf(p_file, " |-Reserved ZERO Field : %d\n", (unsigned int)iphdr->ip_reserved_zero);
	fprintf(p_file, " |-Dont Fragment Field : %d\n", (unsigned int)iphdr->ip_dont_fragment);
	fprintf(p_file, " |-More Fragment Field : %d\n", (unsigned int)iphdr->ip_more_fragment);
	fprintf(p_file, " |-TTL : %d\n", (unsigned int)iphdr->ip_ttl);
	fprintf(p_file, " |-Protocol : %d\n", (unsigned int)iphdr->ip_protocol);
	fprintf(p_file, " |-Checksum : %d\n", ntohs(iphdr->ip_checksum));
	fprintf(p_file, " |-Source IP : %s\n", inet_ntoa(source.sin_addr));
	fprintf(p_file, " |-Destination IP : %s\n", inet_ntoa(dest.sin_addr));
}

void PrintTcpPacket(char* Buffer, int Size)
{
	unsigned short iphdrlen;

	iphdr = (IPV4_HDR *)Buffer;
	iphdrlen = iphdr->ip_header_len * 4;

	tcpheader = (TCP_HDR*)(Buffer + iphdrlen);

	FILE *pFile = TCP_ETC_logfile;

	switch (ntohs(tcpheader->dest_port))
	{
	case 20:
	case 21:
		pFile = TCP_FTP_logfile;
		tcp_ftp++;
		break;
	case 25:
	case 110:
		pFile = TCP_SMTP_logfile;
		tcp_smtp++;
		break;
	case 53:
		pFile = TCP_DNS_logfile;
		tcp_dns++;
		break;
	case 80:
		pFile = TCP_HTTP_logfile;
		tcp_http++;
		break;
	case 443:
		pFile = TCP_HTTPS_logfile;
		tcp_https++;
		break;
	default:
		tcp_etc++;
		break;
	}

	fprintf(pFile, "\n\n***********************TCP Packet*************************\n");

	PrintIpHeader(Buffer, pFile);

	fprintf(pFile, "\n");
	fprintf(pFile, "TCP Header\n");
	fprintf(pFile, " |-Source Port : %u\n", ntohs(tcpheader->source_port));
	fprintf(pFile, " |-Destination Port : %u\n", ntohs(tcpheader->dest_port));
	fprintf(pFile, " |-Sequence Number : %u\n", ntohl(tcpheader->sequence));
	fprintf(pFile, " |-Acknowledge Number : %u\n", ntohl(tcpheader->acknowledge));
	fprintf(pFile, " |-Header Length : %d DWORDS or %d BYTES\n"
		, (unsigned int)tcpheader->data_offset, (unsigned int)tcpheader->data_offset * 4);
	fprintf(pFile, " |-CWR Flag : %d\n", (unsigned int)tcpheader->cwr);
	fprintf(pFile, " |-ECN Flag : %d\n", (unsigned int)tcpheader->ecn);
	fprintf(pFile, " |-Urgent Flag : %d\n", (unsigned int)tcpheader->urg);
	fprintf(pFile, " |-Acknowledgement Flag : %d\n", (unsigned int)tcpheader->ack);
	fprintf(pFile, " |-Push Flag : %d\n", (unsigned int)tcpheader->psh);
	fprintf(pFile, " |-Reset Flag : %d\n", (unsigned int)tcpheader->rst);
	fprintf(pFile, " |-Synchronise Flag : %d\n", (unsigned int)tcpheader->syn);
	fprintf(pFile, " |-Finish Flag : %d\n", (unsigned int)tcpheader->fin);
	fprintf(pFile, " |-Window : %d\n", ntohs(tcpheader->window));
	fprintf(pFile, " |-Checksum : %d\n", ntohs(tcpheader->checksum));
	fprintf(pFile, " |-Urgent Pointer : %d\n", tcpheader->urgent_pointer);
	fprintf(pFile, "\n");
	fprintf(pFile, " DATA Dump\n");
	fprintf(pFile, "\n");

	fprintf(pFile, "IP Header\n");
	PrintData(Buffer, iphdrlen, pFile);

	fprintf(pFile, "TCP Header\n");
	PrintData(Buffer + iphdrlen, tcpheader->data_offset * 4, pFile);

	fprintf(pFile, "Data Payload\n");
	PrintData(Buffer + iphdrlen + tcpheader->data_offset * 4
		, (Size - tcpheader->data_offset * 4 - iphdr->ip_header_len * 4), pFile);

	fprintf(pFile, "\n###########################################################");
}

void PrintUdpPacket(char *Buffer, int Size)
{
	unsigned short iphdrlen;

	iphdr = (IPV4_HDR *)Buffer;
	iphdrlen = iphdr->ip_header_len * 4;

	udpheader = (UDP_HDR *)(Buffer + iphdrlen);

	FILE *pFile = UDP_ETC_logfile;

	switch (ntohs(udpheader->dest_port))
	{
	case 20:
	case 21:
		pFile = UDP_FTP_logfile;
		udp_ftp++;
		break;
	case 25:
	case 110:
		pFile = UDP_SMTP_logfile;
		udp_smtp++;
		break;
	case 53:
		pFile = UDP_DNS_logfile;
		udp_dns++;
		break;
	case 80:
		pFile = UDP_HTTP_logfile;
		udp_http++;
		break;
	case 443:
		pFile = UDP_HTTPS_logfile;
		udp_https++;
		break;
	default:
		udp_etc++;
		break;
	}

	fprintf(pFile, "\n\n***********************UDP Packet*************************\n");

	PrintIpHeader(Buffer, pFile);

	fprintf(pFile, "\nUDP Header\n");
	fprintf(pFile, " |-Source Port : %d\n", ntohs(udpheader->source_port));
	fprintf(pFile, " |-Destination Port : %d\n", ntohs(udpheader->dest_port));
	fprintf(pFile, " |-UDP Length : %d\n", ntohs(udpheader->udp_length));
	fprintf(pFile, " |-UDP Checksum : %d\n", ntohs(udpheader->udp_checksum));

	fprintf(pFile, "\n");
	fprintf(pFile, "IP Header\n");

	PrintData(Buffer, iphdrlen, pFile);

	fprintf(pFile, "UDP Header\n");

	PrintData(Buffer + iphdrlen, sizeof(UDP_HDR), pFile);

	fprintf(pFile, "Data Payload\n");

	PrintData(Buffer + iphdrlen + sizeof(UDP_HDR), (Size - sizeof(UDP_HDR) - iphdr->ip_header_len * 4), pFile);

	fprintf(pFile, "\n###########################################################");
}

void PrintIcmpPacket(char* Buffer, int Size)
{
	unsigned short iphdrlen;

	iphdr = (IPV4_HDR *)Buffer;
	iphdrlen = iphdr->ip_header_len * 4;

	icmpheader = (ICMP_HDR*)(Buffer + iphdrlen);

	fprintf(OTHER_logfile, "\n\n***********************ICMP Packet*************************\n");
	PrintIpHeader(Buffer, OTHER_logfile);

	fprintf(OTHER_logfile, "\n");

	fprintf(OTHER_logfile, "ICMP Header\n");
	fprintf(OTHER_logfile, " |-Type : %d", (unsigned int)(icmpheader->type));

	if ((unsigned int)(icmpheader->type) == 11)
	{
		fprintf(OTHER_logfile, " (TTL Expired)\n");
	}
	else if ((unsigned int)(icmpheader->type) == 0)
	{
		fprintf(OTHER_logfile, " (ICMP Echo Reply)\n");
	}

	fprintf(OTHER_logfile, " |-Code : %d\n", (unsigned int)(icmpheader->code));
	fprintf(OTHER_logfile, " |-Checksum : %d\n", ntohs(icmpheader->checksum));
	fprintf(OTHER_logfile, " |-ID : %d\n", ntohs(icmpheader->id));
	fprintf(OTHER_logfile, " |-Sequence : %d\n", ntohs(icmpheader->seq));
	fprintf(OTHER_logfile, "\n");

	fprintf(OTHER_logfile, "IP Header\n");
	PrintData(Buffer, iphdrlen, OTHER_logfile);

	fprintf(OTHER_logfile, "UDP Header\n");
	PrintData(Buffer + iphdrlen, sizeof(ICMP_HDR), OTHER_logfile);

	fprintf(OTHER_logfile, "Data Payload\n");
	PrintData(Buffer + iphdrlen + sizeof(ICMP_HDR), (Size - sizeof(ICMP_HDR) - iphdr->ip_header_len * 4), OTHER_logfile);

	fprintf(OTHER_logfile, "\n###########################################################");
}

/*
Print the hex values of the data
*/
void PrintData(char* data, int Size, FILE* p_file)
{
	char a, line[17], c;
	int j;

	//loop over each character and print
	for (i = 0; i < Size; i++)
	{
		c = data[i];

		//Print the hex value for every character , with a space. Important to make unsigned
		fprintf(p_file, " %.2x", (unsigned char)c);

		//Add the character to data line. Important to make unsigned
		a = (c >= 32 && c <= 128) ? (unsigned char)c : '.';

		line[i % 16] = a;

		//if last character of a line , then print the line - 16 characters in 1 line
		if ((i != 0 && (i + 1) % 16 == 0) || i == Size - 1)
		{
			line[i % 16 + 1] = '\0';

			//print a big gap of 10 characters between hex and characters
			fprintf(p_file, "          ");

			//Print additional spaces for last lines which might be less than 16 characters in length
			for (j = strlen(line); j < 16; j++)
			{
				fprintf(p_file, "   ");
			}

			fprintf(p_file, "%s \n", line);
		}
	}

	fprintf(p_file, "\n");
}