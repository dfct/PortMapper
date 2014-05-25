//Port Mapper - Intercept and remap TCP or UDP traffic over ports of your choosing.
//

#include <winsock2.h>								//Provides functions for TCP/IP network byte order & host byte conversions 
#include "windivert.h"								//WinDivert functions and types
#include <iostream>									//Console output
#include <vector>									//Storing port types & numbers
#include <string>									//Building the filter string for WinDivert

#pragma comment(lib, "WinDivert.lib")				//WinDivert library
#pragma comment(lib, "ws2_32.lib")					//And the library for TCP/IP network byte order & host byte conversions 

char version[] = { "0.0.1" };						//Version, printed in help output

void showHelp();									//Print help text
bool parsePorts(char argv[]);						//Function to parse passed in port map data from the command line
int ModifyPacket(PVOID pPacket, UINT packet_len);	//Function modifies the incoming/outgoing packet as requested
int PrintPacket(PVOID pPacket, UINT packet_len, bool modified);	//Function prints packet data for debugging purposes

#define type_tcp 0
#define type_udp 1

struct portInfo {									//Struct used to track what ports to map
	int pmType;
	int pmFrom;
	int pmTo;
};

std::vector<portInfo> portMap(0);					//Vector to allow easy variance in how many to track
std::string filterString;							//Filter string for WinDivert



int main(int argc, char * argv[])
{
	bool showDebugInformation = false;

	//Parse switches. Must have at least three to be a valid set
	if (argc >= 3 && strcmp(argv[1], "/remap") == 0)
	{
		//Parse for all parameters after /remap
		for (int i = 2; i < argc; i++)
		{
			if (strcmp(argv[i], "/debug") == 0)
			{
				//Valid info, move to the next parameter
				showDebugInformation = true;
				continue;
			}
			else if (parsePorts(argv[i]))
			{
				//Valid info, move to the next parameter
				continue;
			}
			else
			{
				//Bad info, error and exit
				fprintf(stderr, "\nUnrecognized command line parameter passed. Run /? for help. \n\n");
				return 1;
			}
		}
	}
	else
	{
		showHelp();
		return 0;
	}


	//Build the WinDivert filter string from the port data 
	filterString = "(";

	for (UINT i = 0; i < portMap.size(); i++)
	{
		if (portMap[i].pmType == type_tcp)
		{
			filterString += "tcp.DstPort == " + std::to_string(portMap[i].pmFrom) + " or tcp.SrcPort == " + std::to_string(portMap[i].pmTo);
		}
		else if (portMap[i].pmType == type_udp)
		{
			filterString += "udp.DstPort == " + std::to_string(portMap[i].pmFrom) + " or udp.SrcPort == " + std::to_string(portMap[i].pmTo);
		}

		if (!(portMap.size() == i + 1))
		{
			filterString += " or ";
		}
	}

	filterString += ")";

	//Open a handle with WinDivert 
	HANDLE wdHandle = WinDivertOpen(filterString.c_str(), WINDIVERT_LAYER_NETWORK, 0, 0);	

	//If the handle is invalid, error and exit
	if (wdHandle == INVALID_HANDLE_VALUE)
	{
		HRESULT whyNot = GetLastError();
		fprintf(stderr, "Unable to initialize WinDivert (%d).", whyNot);
		
		if (whyNot = 87)
		{
			fprintf(stderr, " This is usually caused by an error in the filter syntax.\n");
		}

		return whyNot;
	}



	unsigned char packet[0xFFFF] = { 0 };			//Captured Packet
	UINT packet_len = 0;							//Length of captured packet
	WINDIVERT_ADDRESS addr;							//Direction of captured packet (incoming or outgoing)


	//Debug packet capture loop
	while (showDebugInformation)
	{
		// Read a matching packet.
		if (!WinDivertRecv(wdHandle, packet, sizeof(packet), &addr, &packet_len))
		{
			fprintf(stderr, "\nwarning: failed to read packet (%d)\n", GetLastError());
			continue;
		}
		
		//Print, Modify, Print the incoming/outgoing packets 
		PrintPacket((PVOID)packet, packet_len, false);
		ModifyPacket((PVOID)packet, packet_len);
		PrintPacket((PVOID)packet, packet_len, true);

		// Send the packet on its way
		if (!WinDivertSend(wdHandle, (PVOID)packet, packet_len, &addr, NULL))
		{
			fprintf(stderr, "\nwarning: failed to send packet (%d)\n", GetLastError());
		}
	}


	//Regular loop for non-debug runs
	while (TRUE)
	{
		if (WinDivertRecv(wdHandle, packet, sizeof(packet), &addr, &packet_len))	//Read a matching packet.
		{
			ModifyPacket((PVOID)packet, packet_len);								//Modify the incoming/outgoing packets as needed to reach Azure VM
			WinDivertSend(wdHandle, (PVOID)packet, packet_len, &addr, NULL);		//Send the packet on its way
		}
	}

}

bool parsePorts(char argv[])
{
	//Quick variable for the type of data, tcp or udp
	int tempPMType;

	if (!strncmp("tcp:", argv, 4))
	{
		tempPMType = type_tcp;
	}
	else if (!strncmp("udp:", argv, 4))
	{
		tempPMType = type_udp;
	}
	else
	{
		//Bad data
		return false;
	}


	//Move the char pointer past tcp:/udp:
	char * charPortFrom = &argv[4];
	
	//Create a new char pointer and set it to the second half of the data, as matched by the : in the string
	char * charPortTo;
	charPortTo = strchr(charPortFrom, 58);

	if (charPortTo == NULL)
	{
		//Bad data
		return false;
	}

	charPortTo++; //move up one char to step past :	
	memset((charPortTo - 1), 0, sizeof(char)); //Null the : to terminate charPortFrom appropriately

	//Check that the port numbers of each are proper digits
	for (size_t i = 0; i < strlen(charPortFrom); i++)
	{
		if (!isdigit(charPortFrom[i]))
		{
			return false;
		}
	}
	for (size_t i = 0; i < strlen(charPortTo); i++)
	{
		if (!isdigit(charPortTo[i]))
		{
			return false;
		}
	}

	//Add the data to the vector of portInfos
	portMap.push_back({ tempPMType, atoi(charPortFrom), atoi(charPortTo) });

	return true;
}

inline int ModifyPacket(PVOID pPacket, UINT packetLen)
{
	if (pPacket == NULL)
	{
		return 0;
	}

	if (((((PWINDIVERT_IPHDR)pPacket)->Protocol) == IPPROTO_TCP))
	{
		//Move past the IP header to the TCP header
		PWINDIVERT_TCPHDR tcp_header = (PWINDIVERT_TCPHDR)((UINT8 *)pPacket + ((PWINDIVERT_IPHDR)pPacket)->HdrLength*sizeof(UINT32)); 

		for (UINT i = 0; i < portMap.size(); i++)
		{
			if (portMap[i].pmType == type_tcp)
			{
				if (tcp_header->DstPort == htons(portMap[i].pmFrom))	
					tcp_header->DstPort = htons(portMap[i].pmTo);		

				if (tcp_header->SrcPort == htons(portMap[i].pmTo))
					tcp_header->SrcPort = htons(portMap[i].pmFrom);
			}
		}
	}

	if (((((PWINDIVERT_IPHDR)pPacket)->Protocol) == IPPROTO_UDP))
	{
		//Move past the IP header to the UDP header
		PWINDIVERT_UDPHDR udp_header = (PWINDIVERT_UDPHDR)((UINT8 *)pPacket + ((PWINDIVERT_IPHDR)pPacket)->HdrLength*sizeof(UINT32)); 

		for (UINT i = 0; i < portMap.size(); i++)
		{
			if (portMap[i].pmType == type_tcp)
			{
				if (udp_header->DstPort == htons(portMap[i].pmFrom))
					udp_header->DstPort = htons(portMap[i].pmTo);

				if (udp_header->SrcPort == htons(portMap[i].pmTo))
					udp_header->SrcPort = htons(portMap[i].pmFrom);
			}
		}
	}

	
	WinDivertHelperCalcChecksums((PVOID)pPacket, packetLen, WINDIVERT_HELPER_NO_IP_CHECKSUM | WINDIVERT_HELPER_NO_ICMP_CHECKSUM | WINDIVERT_HELPER_NO_ICMPV6_CHECKSUM);

	return 0;
}

int PrintPacket(PVOID pPacket, UINT packet_len, bool modified)
{
	HANDLE console;
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_UDPHDR udp_header;
	UINT payload_len;

	//Get console for pretty colors.
	console = GetStdHandle(STD_OUTPUT_HANDLE);

	//Parse packet info
	WinDivertHelperParsePacket(pPacket, packet_len, &ip_header, NULL, NULL, NULL, &tcp_header, &udp_header, NULL, &payload_len);

	if (ip_header == NULL)
	{
		printf("Wat");
		return 0;
	}

	//Print packet info
	SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

	if (ip_header != NULL)
	{
		UINT8 *src_addr = (UINT8 *)&ip_header->SrcAddr;
		UINT8 *dst_addr = (UINT8 *)&ip_header->DstAddr;
		printf("ip.SrcAddr=%u.%u.%u.%u ip.DstAddr=%u.%u.%u.%u ",
			src_addr[0], src_addr[1], src_addr[2], src_addr[3],
			dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
	}
	if (tcp_header != NULL)
	{
		if (modified)
		{
			SetConsoleTextAttribute(console, FOREGROUND_GREEN);
		}
		else
		{
			SetConsoleTextAttribute(console, FOREGROUND_BLUE);
		}

		printf("tcp.SrcPort=%u tcp.DstPort=%u tcp.Flags=", ntohs(tcp_header->SrcPort), ntohs(tcp_header->DstPort));

		//Back to black
		SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

		if (tcp_header->Fin)
		{
			fputs("[FIN]", stdout);
		}
		if (tcp_header->Rst)
		{
			fputs("[RST]", stdout);
		}
		if (tcp_header->Urg)
		{
			fputs("[URG]", stdout);
		}
		if (tcp_header->Syn)
		{
			fputs("[SYN]", stdout);
		}
		if (tcp_header->Psh)
		{
			fputs("[PSH]", stdout);
		}
		if (tcp_header->Ack)
		{
			fputs("[ACK]", stdout);
		}
		putchar(' ');
		printf("\n");
	}
	if (udp_header != NULL)
	{
		if (modified)
		{
			SetConsoleTextAttribute(console, FOREGROUND_GREEN);
		}
		else
		{
			SetConsoleTextAttribute(console, FOREGROUND_BLUE);
		}

		printf("udp.SrcPort=%u udp.DstPort=%u ", ntohs(udp_header->SrcPort), ntohs(udp_header->DstPort));
		putchar(' ');
		printf("\n");

		//Back to black
		SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

	}
	return 0;
}

void showHelp()
{
	std::cout << "\nPort Mapper - Intercept & remap TCP or UDP traffic over ports of your choosing.\n"
		<< "\nVersion: " << version << "\n"
		<< "\n"
		<< "   /remap [tcp:#:# | udp:#:#]  [/debug]\n"
		<< "\n"
		<< "      /remap [tcp:#:# | udp:#:#]    Specifies which TCP/UDP ports to remap. You\n"
		<< "                                    may provide more than one set to remap.\n"
		<< "                                    Format is protocol:currentport:newport \n"
		<< "\n"
		<< "      /debug                        Print all packets before/after modification\n"
		<< "\n"
		<< "\n"
		<< "Examples: \n"
		<< "      portmapper.exe /remap tcp:80:8080 \n"
		<< "      portmapper.exe /remap udp:5000:6767 tcp:25:443 tcp:500:125 /debug\n"
		<< "\n";

	return;
}