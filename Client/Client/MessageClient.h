#pragma once

#include "TcpClient.h"
#include "Requests.h"

const std::string USER_INFO_FILE_NAME = "me.info";
const std::string SERVERS_INFO_FILE_NAME = "srv.info";

// Single messaging server, so according to forum answer this field is ignored.
constexpr ServerId SERVER_ID = {0};

constexpr int USERNAME_LINE_INDEX = 0;
constexpr int CLIENT_ID_LINE_INDEX = 1;

constexpr int AUTH_SERVER_ADDR_LINE_INDEX = 0;
constexpr int MESSAGE_SERVER_ADDR_LINE_INDEX = 1;

constexpr int IV_LENGTH = 16;
constexpr int NONCE_LENGTH = 8;
constexpr int AES_KEY_LENGTH = 32;

class MessageClient
{
public:
	MessageClient();

private:
	void registerUser();

	void acquireSymmetricKey();

	void communicateWithMessageServer();

	[[nodiscard]] Buffer sendRequest(const Request& request, int expectedCode) const;

	[[nodiscard]] std::pair<std::string, uint16_t> addrToIpAndPort(const std::string& addr) const;

	void validateServersInfoFile() const;

	static uint64_t generateRandomNonce();

	TcpClient m_tcpClient;
	std::string m_username;
	std::string m_password;
	ClientId m_clientId;
	std::string m_aesKey;

	std::string m_msgServerIp;
	uint16_t m_msgServerPort;
	std::string m_ticket;
};
