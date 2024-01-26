#include "FileClient.h"

#include "Base64Wrapper.h"
#include "Checksum.h"
#include "File.h"
#include "Responses.h"
#include "RsaWrapper.h"
#include "AesWrapper.h"

#include <filesystem>
#include <iostream>
#include <fstream>

FileClient::FileClient()
	: m_clientId()
{
	validateTransferFile();

	std::vector<std::string> lines = readFileLines(TRANSFER_INFO_FILE_NAME);
	std::string serverAddr = lines[SERVER_ADDR_LINE_INDEX];
	m_username = lines[CLIENT_NAME_LINE_INDEX];
	m_pathOfFileToSend = lines[FILE_PATH_LINE_INDEX];
	auto [serverIp, serverPort] = addrToIpAndPort(serverAddr);

	std::cout << "Server is at " << serverIp << ":" << serverPort << std::endl;
	std::cout << "Username is " << m_username << std::endl;
	std::cout << "File to send is " << m_pathOfFileToSend << std::endl;

	m_tcpClient.connectToServer(serverIp, serverPort);

	if (std::filesystem::exists(USER_INFO_FILE_NAME))
	{
		reconnect();
	}
	else
	{
		registerUser();
	}

	// Decrypt the AES key by using the private RSA key.
	RsaPrivateWrapper rsaWrapperOther(m_privateKey);
	m_aesKey = rsaWrapperOther.decrypt(m_encryptedAesKey);
}

void FileClient::registerUser()
{
	std::cout << USER_INFO_FILE_NAME << " does not exist. Using username from " << TRANSFER_INFO_FILE_NAME << std::endl;

	std::cout << "Sending registration request to the server" << std::endl;

	RegistrationRequest registrationRequest(m_username);

	Buffer receivedData = trySendingRequest(registrationRequest, RegistrationSuccessResponse::getExpectedCode());

	RegistrationSuccessResponse registrationResponse(receivedData);

	m_clientId = registrationResponse.getClientId();
	std::string clientIdAsAscii = registrationResponse.getClientIdAsAscii();

	std::cout << "Writing username and received ID to " << USER_INFO_FILE_NAME << std::endl;
	std::stringstream ss;
	ss << m_username << std::endl << clientIdAsAscii << std::endl;
	writeToFile(USER_INFO_FILE_NAME, ss);

	std::cout << "Creating RSA key pair" << std::endl;
	RsaPrivateWrapper rsaWrapper;
	m_privateKey = rsaWrapper.getPrivateKey();
	std::string publicKey = rsaWrapper.getPublicKey();

	std::cout << "Writing private key to " << PRIVATE_KEY_FILE_NAME << std::endl;
	std::ofstream privateKeyFile(PRIVATE_KEY_FILE_NAME);
	writeToBinaryFile(PRIVATE_KEY_FILE_NAME, m_privateKey);

	std::cout << "Writing base64 encoded private key to " << USER_INFO_FILE_NAME << std::endl;
	std::string base64privateKey = Base64Wrapper::encode(m_privateKey);
	writeToFile(USER_INFO_FILE_NAME, base64privateKey, true);

	std::cout << "Sending public key to the server" << std::endl;
	ClientPublicKeyRequest publicKeyRequest(m_username, m_clientId, publicKey);
	receivedData = trySendingRequest(publicKeyRequest, KeyResponse::getExpectedCode());

	KeyResponse keyResponse(receivedData);
	m_encryptedAesKey = keyResponse.getEncryptedAesKey();
}

void FileClient::reconnect()
{
	std::cout << "Found " << USER_INFO_FILE_NAME << ". Reading username from it" << std::endl;

	std::vector<std::string> lines = readFileLines(USER_INFO_FILE_NAME);
	m_username = lines[USERNAME_LINE_INDEX];
	std::string clientIdAscii = lines[CLIENT_ID_LINE_INDEX];

	for (size_t i = 0; i < clientIdAscii.length(); i += 2)
	{
		std::string byteString = clientIdAscii.substr(i, 2);
		m_clientId[i / 2] = static_cast<uint8_t>(std::stoi(byteString, 0, 16));
	}

	std::cout << "Sending reconnect request to the server" << std::endl;
	ReconnectRequest reconnectRequest(m_username, m_clientId);

	Buffer receivedData = m_tcpClient.sendAndReceive(reconnectRequest.serialize());
	uint16_t code = getResponseCode(receivedData.data());
	if (code == RejectedReconnectResponse::getExpectedCode())
	{
		return registerUser();
	}
	if (code != AcceptReconnectResponse::getExpectedCode())
	{
		throw std::runtime_error("Fatal: Server responded with an error " + std::to_string(code));
	}

	AcceptReconnectResponse acceptReconnectResponse(receivedData);
	m_encryptedAesKey = acceptReconnectResponse.getEncryptedAesKey();

	Buffer privateKeyBuf = readBinaryFile(PRIVATE_KEY_FILE_NAME);
	m_privateKey = std::string(privateKeyBuf.data(), privateKeyBuf.size());
}

void FileClient::sendFile() const
{
	// Read the file to send
	Buffer fileBuffer = readBinaryFile(m_pathOfFileToSend);

	// Calc CRC of the file to send
	uint32_t fileCrc = memcrc(fileBuffer.data(), fileBuffer.size());
	std::cout << m_pathOfFileToSend << " CRC is " << fileCrc << std::endl;

	// Encrypt the file to send with the AES key
	AesWrapper aesWrapper(m_aesKey);
	std::string encryptedFile = aesWrapper.encrypt(fileBuffer.data(), static_cast<uint32_t>(fileBuffer.size()));
	Buffer encryptedFileBuf(encryptedFile.begin(), encryptedFile.end());

	std::string nameOfFileToSend = std::filesystem::path(m_pathOfFileToSend).filename().string();
	SendFileRequest sendFileRequest(nameOfFileToSend, m_clientId, encryptedFileBuf);

	constexpr int NUM_OF_TRIES = 4;
	int tryNum = 1;
	uint32_t receivedCrc;
	do
	{
		std::cout << "Sending encrypted " << nameOfFileToSend << " to server" << std::endl;
		Buffer receivedData = trySendingRequest(sendFileRequest, ReceivedFileResponse::getExpectedCode());

		ReceivedFileResponse fileResponse(receivedData);
		receivedCrc = fileResponse.getChecksum();

		std::cout << "attempt " << std::to_string(tryNum) << "/" << std::to_string(NUM_OF_TRIES) << std::endl;
		InvalidCrcRequest invalidCrcRequest(nameOfFileToSend, m_clientId);
		m_tcpClient.sendData(invalidCrcRequest.serialize());

		tryNum++;
	}
	while (receivedCrc != fileCrc && tryNum <= NUM_OF_TRIES);

	if (receivedCrc == fileCrc)
	{
		std::cout << "File received successfully" << std::endl;
		ValidCrcRequest validCrcRequest(nameOfFileToSend, m_clientId);
		m_tcpClient.sendData(validCrcRequest.serialize());
	}
	else
	{
		std::cout << "Failed, aborting" << std::endl;
		LastInvalidCrcRequest lastInvalidCrcRequest(nameOfFileToSend, m_clientId);
		m_tcpClient.sendData(lastInvalidCrcRequest.serialize());
	}
}

Buffer FileClient::trySendingRequest(const Request& request, int expectedCode) const
{
	constexpr int REQ_NUM_OF_TRIES = 4;
	int tryNum = 1;

	uint16_t code;
	Buffer receivedData;

	do
	{
		receivedData  = m_tcpClient.sendAndReceive(request.serialize());
		code = getResponseCode(receivedData.data());

		if (code != expectedCode)
			std::cout << "Server responded with an error " << std::to_string(code) << std::endl;

		tryNum++;
	}
	while (code != expectedCode && tryNum <= REQ_NUM_OF_TRIES);

	if (code == expectedCode)
	{
		return receivedData;
	}

	throw std::runtime_error("Fatal: Server responded with an error " + std::to_string(code));
}

std::pair<std::string, uint16_t> FileClient::addrToIpAndPort(const std::string& addr) const
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

void FileClient::validateTransferFile() const
{
	if (!std::filesystem::exists(TRANSFER_INFO_FILE_NAME))
	{
		throw std::runtime_error(TRANSFER_INFO_FILE_NAME + " does not exist");
	}

	const std::vector<std::string> lines = readFileLines(TRANSFER_INFO_FILE_NAME);
	const size_t fileNumOfLines = lines.size();

	constexpr int TRANSFER_INFO_FILE_NAME_REQUIRED_NUM_OF_LINES = 3;
	if (fileNumOfLines < TRANSFER_INFO_FILE_NAME_REQUIRED_NUM_OF_LINES)
	{
		throw std::runtime_error(TRANSFER_INFO_FILE_NAME + " has an unexpected number of lines");
	}
}
