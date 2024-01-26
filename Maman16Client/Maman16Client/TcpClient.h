#pragma once

#include "Macros.h"
#include "Defs.h"

#include <cstdint>
#include <string>
#include <vector>

#include <ws2tcpip.h>

class TcpClient
{
public:
	TcpClient();

	DELETE_COPY(TcpClient);

	DELETE_MOVE(TcpClient);

	~TcpClient();

	void connectToServer(const std::string& serverIp, uint16_t serverPort);

	int sendData(const Buffer& buffer) const;

	[[nodiscard]] Buffer receiveData() const;

	Buffer sendAndReceive(const Buffer& buffer) const;

private:
	SOCKET m_socket;
	bool m_connected;
};
