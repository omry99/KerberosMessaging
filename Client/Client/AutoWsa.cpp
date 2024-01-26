#include "AutoWsa.h"
#include <stdexcept>
#include <WinSock2.h>

#pragma comment(lib, "Ws2_32.lib")

AutoWsa::AutoWsa()
{
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) 
	{
		throw std::runtime_error("WSAStartup failed");
	}
}

AutoWsa::~AutoWsa()
{
	WSACleanup();
}
