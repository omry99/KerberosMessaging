#include "MessageClient.h"

#include "File.h"
#include "Responses.h"
#include "AesWrapper.h"
#include "Hash.h"

#include <filesystem>
#include <iostream>
#include <fstream>
#include <random>

MessageClient::MessageClient()
	: m_clientId()
{
	validateServersInfoFile();

	std::vector<std::string> lines = readFileLines(SERVERS_INFO_FILE_NAME);
	std::string authServerAddr = lines[AUTH_SERVER_ADDR_LINE_INDEX];
	std::string msgServerAddr = lines[MESSAGE_SERVER_ADDR_LINE_INDEX];

	auto [authServerIp, authServerPort] = addrToIpAndPort(authServerAddr);
	auto [msgServerIp, msgServerPort] = addrToIpAndPort(msgServerAddr);
	m_msgServerIp = msgServerIp;
	m_msgServerPort = msgServerPort;

	std::cout << "KDC is at " << authServerIp << ":" << authServerPort << std::endl;
	std::cout << "Message server is at " << m_msgServerIp << ":" << m_msgServerPort << std::endl;

	m_tcpClient.connectToServer(authServerIp, authServerPort);

	if (std::filesystem::exists(USER_INFO_FILE_NAME))
	{
		lines = readFileLines(USER_INFO_FILE_NAME);
		m_username = lines[USERNAME_LINE_INDEX];
		std::string clientIdAsAscii = lines[CLIENT_ID_LINE_INDEX];

		for (size_t i = 0; i < clientIdAsAscii.length(); i += 2)
		{
			std::string byteString = clientIdAsAscii.substr(i, 2);
			m_clientId[i / 2] = static_cast<uint8_t>(std::stoi(byteString, 0, 16));
		}

		std::cout << "Enter password: ";
		std::cin >> m_password;
	}
	else
	{
		registerUser();
	}
	
	acquireSymmetricKey();

	communicateWithMessageServer();
}

void MessageClient::registerUser()
{
	std::cout << USER_INFO_FILE_NAME << " does not exist. Getting credentials from user " << std::endl;

	std::cout << "Enter username: ";
	std::cin >> m_username;
	std::cout << "Enter password: ";
	std::cin >> m_password;

	std::cout << "Sending registration request to the server" << std::endl;
	RegistrationRequest registrationRequest(m_username, m_password);

	Buffer receivedData = sendRequest(registrationRequest, RegistrationSuccessResponse::getExpectedCode());

	RegistrationSuccessResponse registrationResponse(receivedData);

	m_clientId = registrationResponse.getClientId();
	std::string clientIdAsAscii = registrationResponse.getClientIdAsAscii();

	std::cout << "Writing username and received ID to " << USER_INFO_FILE_NAME << std::endl;
	std::stringstream ss;
	ss << m_username << std::endl << clientIdAsAscii << std::endl;
	writeToFile(USER_INFO_FILE_NAME, ss);
}

void MessageClient::acquireSymmetricKey()
{
	uint64_t nonce = generateRandomNonce();

	std::cout << "Sending symmetric key request to authentication server" << std::endl;
	SymmetricKeyRequest symmetricKeyRequest(m_clientId, SERVER_ID, nonce);
	Buffer receivedData = sendRequest(symmetricKeyRequest, SymmetricKeyResponse::getExpectedCode());
	//writeToBinaryFile("C:\\Users\\User\\AppData\\Roaming\\JetBrains\\PyCharm2022.1\\scratches\\symmetricKeyResponse.bin", receivedData);
	writeToBinaryFile("C:\\temp\\symmetricKeyResponse.bin", receivedData);

	SymmetricKeyResponse keyResponse(receivedData);
	m_ticket = keyResponse.getTicket();
	auto encryptedKey = keyResponse.getEncryptedKey();

	// Get the cleartext AES key
	std::string passHash = calculateSha256Hash(m_password);
	AesWrapper aesWrapper(passHash);
	auto encryptedKeyIv = std::string(encryptedKey.data(), IV_LENGTH);
	std::string decryptedKey;
	try
	{
		decryptedKey = aesWrapper.decrypt(encryptedKey.data() + encryptedKeyIv.size(), static_cast<uint32_t>(encryptedKey.size() - encryptedKeyIv.size()), encryptedKeyIv);
	}
	catch (const CryptoPP::InvalidCiphertext&)
	{ 
		throw std::runtime_error("Decryption failed, meaning provided password is incorrect");
	}
	m_aesKey = std::string(decryptedKey.data() + NONCE_LENGTH, AES_KEY_LENGTH);
}

void MessageClient::communicateWithMessageServer()
{
	Authenticator authenticator(m_aesKey, m_clientId, SERVER_ID);

	m_tcpClient = TcpClient();
	m_tcpClient.connectToServer(m_msgServerIp, m_msgServerPort);

	std::cout << "Sending symmetric key to messaging server" << std::endl;
	SendSymmetricKeyRequest sendSymmetricKeyRequest(m_clientId, authenticator, m_ticket);
	Buffer receivedData = sendRequest(sendSymmetricKeyRequest, ReceivedSymmetricKeyResponse::getExpectedCode());

	std::cout << "Sending message to messaging server" << std::endl;
	std::cout << "Enter message to send: ";
	std::string msg;
	std::cin >> msg;
	AesWrapper aesWrapperOther(m_aesKey);
	auto [encryptedMsg, msgIv] = aesWrapperOther.encrypt(msg.data(), static_cast<uint32_t>(msg.size()));
	auto encryptedMsgSize = static_cast<uint32_t>(encryptedMsg.size());

	SendMessageRequest sendMessageRequest(m_clientId, encryptedMsgSize, msgIv, encryptedMsg);
	receivedData = sendRequest(sendMessageRequest, ReceivedMessageResponse::getExpectedCode());
}

Buffer MessageClient::sendRequest(const Request& request, int expectedCode) const
{
	Buffer receivedData  = m_tcpClient.sendAndReceive(request.serialize());
	uint16_t responseCode = getResponseCode(receivedData.data());

	if (responseCode != expectedCode)
		throw std::runtime_error("Fatal: Server responded with an error " + std::to_string(responseCode));

	return receivedData;
}

std::pair<std::string, uint16_t> MessageClient::addrToIpAndPort(const std::string& addr) const
{
	size_t colonPos = addr.find(':');

	if (colonPos == std::string::npos)
	{
		throw std::runtime_error("Invalid address, not <ip>:<port> format");
	}

	std::string ip = addr.substr(0, colonPos);
	uint16_t port = static_cast<uint16_t>(std::stoul(addr.substr(colonPos + 1)));

	return {ip, port};
}

void MessageClient::validateServersInfoFile() const
{
	if (!std::filesystem::exists(SERVERS_INFO_FILE_NAME))
	{
		throw std::runtime_error(SERVERS_INFO_FILE_NAME + " does not exist");
	}

	const std::vector<std::string> lines = readFileLines(SERVERS_INFO_FILE_NAME);
	const size_t fileNumOfLines = lines.size();

	constexpr int SERVERS_INFO_FILE_REQUIRED_NUM_OF_LINES = 2;
	if (fileNumOfLines < SERVERS_INFO_FILE_REQUIRED_NUM_OF_LINES)
	{
		throw std::runtime_error(SERVERS_INFO_FILE_NAME + " has an unexpected number of lines");
	}
}

uint64_t MessageClient::generateRandomNonce()
{
	std::random_device rd;
	std::mt19937_64 gen(rd());
	std::uniform_int_distribution<uint64_t> distribution;
	return distribution(gen);
}
