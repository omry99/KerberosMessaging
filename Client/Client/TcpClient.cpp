#include "TcpClient.h"

#include <iostream>
#include <stdexcept>

TcpClient::TcpClient()
{
	m_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (m_socket == INVALID_SOCKET)
	{
		throw std::runtime_error("Failed to create socket with error code " + std::to_string(WSAGetLastError()));
	}

	m_connected = false;
}

TcpClient::~TcpClient()
{
	try
	{
		disconnect();
	}
	catch (...)
	{
		std::cout << "Caught an exception in ~TcpClient" << std::endl;
	}
}

void TcpClient::disconnect()
{
	if (!m_connected)
	{
		return;
	}

	if (m_socket != INVALID_SOCKET)
	{
		if (closesocket(m_socket) == SOCKET_ERROR)
		{
			throw std::runtime_error("closesocket failed with error code " + std::to_string(WSAGetLastError()));
		}
	}

	m_connected = false;
}

void TcpClient::connectToServer(const std::string& serverIp, uint16_t serverPort)
{
	if (m_connected)
	{
		throw std::runtime_error("Already connected to a server.");
	}

	sockaddr_in serverAddress{};
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_port = htons(serverPort);

	constexpr int INET_PTON_SUCCESS = 1;
	if (inet_pton(AF_INET, serverIp.c_str(), &(serverAddress.sin_addr.s_addr)) != INET_PTON_SUCCESS)
	{
		throw std::runtime_error("inet_pton failed with error code " + std::to_string(WSAGetLastError()));
	}

	if (connect(m_socket, reinterpret_cast<sockaddr*>(&serverAddress), sizeof(serverAddress)) == SOCKET_ERROR)
	{
		throw std::runtime_error("Failed to connect to the server with error code " + std::to_string(WSAGetLastError()));
	}

	m_connected = true;
}

int TcpClient::sendData(const Buffer& buffer) const
{
	if (!m_connected)
	{
		throw std::runtime_error("Cannot send if not connected.");
	}

	int bytesSent = send(m_socket, buffer.data(), static_cast<int>(buffer.size()), 0);
	if (bytesSent == SOCKET_ERROR)
	{
		throw std::runtime_error("Failed to send data with error code " + std::to_string(WSAGetLastError()));
	}

	return bytesSent;
}

Buffer TcpClient::receiveData() const
{
	if (!m_connected)
	{
		throw std::runtime_error("Cannot receive if not connected.");
	}

	constexpr size_t BUFFER_SIZE = 1024;
	Buffer rcvBuffer(BUFFER_SIZE);
	int bytesReceived = recv(m_socket, rcvBuffer.data(), BUFFER_SIZE, 0);
	if (bytesReceived == SOCKET_ERROR)
	{
		throw std::runtime_error("Failed to receive data with error code " + std::to_string(WSAGetLastError()));
	}

	return rcvBuffer;
}

Buffer TcpClient::sendAndReceive(const Buffer& buffer) const
{
	sendData(buffer);
	Buffer rcvBuffer = receiveData();

	return rcvBuffer;
}
