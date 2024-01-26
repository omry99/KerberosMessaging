#pragma once

#include "TcpClient.h"
#include "Requests.h"

const std::string USER_INFO_FILE_NAME = "me.info";
const std::string TRANSFER_INFO_FILE_NAME = "transfer.info";
const std::string PRIVATE_KEY_FILE_NAME = "priv.key";

constexpr int USERNAME_LINE_INDEX = 0;
constexpr int CLIENT_ID_LINE_INDEX = 1;

constexpr int SERVER_ADDR_LINE_INDEX = 0;
constexpr int CLIENT_NAME_LINE_INDEX = 1;
constexpr int FILE_PATH_LINE_INDEX = 2;

class FileClient
{
public:
	FileClient();

	void sendFile() const;

private:
	void registerUser();

	void reconnect();

	[[nodiscard]] Buffer trySendingRequest(const Request& request, int expectedCode) const;

	[[nodiscard]] std::pair<std::string, uint16_t> addrToIpAndPort(const std::string& addr) const;

	void validateTransferFile() const;

	TcpClient m_tcpClient;
	std::string m_username;
	ClientId m_clientId;
	std::string m_encryptedAesKey;
	std::string m_privateKey;
	std::string m_aesKey;
	std::string m_pathOfFileToSend;
};
