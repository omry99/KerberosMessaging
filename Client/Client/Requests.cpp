#include "Requests.h"

Buffer Request::serialize() const
{
	Buffer data;

	for (uint8_t c : m_clientId)
	{
		data.push_back(c);
	}

	data.push_back(m_version);
	data.push_back(m_code & 0xFF);
	data.push_back(m_code >> 8 & 0xFF);
	data.push_back(m_payloadSize & 0xFF);
	data.push_back(m_payloadSize >> 8 & 0xFF);
	data.push_back(m_payloadSize >> 16 & 0xFF);
	data.push_back(m_payloadSize >> 24 & 0xFF);

	data.insert(data.end(), m_payload.begin(), m_payload.end());

	return data;
}

Request::Request(const ClientId& clientId, uint16_t code)
	: m_clientId(clientId), m_code(code), m_payloadSize(0)
{
}

RegistrationRequest::RegistrationRequest(const std::string& username,
                                         const std::string& password):
	Request(ClientId{0}, 1024)
{
	std::string paddedUsername = username;
	paddedUsername.insert(paddedUsername.end(), USERNAME_FIELD_SIZE - paddedUsername.size(), '\0');
	std::string paddedPassword = password;
	paddedPassword.insert(paddedPassword.end(), PASSWORD_FIELD_SIZE - paddedUsername.size(), '\0');

	m_payloadSize = static_cast<uint32_t>(paddedUsername.size()) + static_cast<uint32_t>(paddedPassword.size());
	m_payload.insert(m_payload.end(), paddedUsername.begin(), paddedUsername.end());
	m_payload.insert(m_payload.end(), paddedPassword.begin(), paddedPassword.end());
}

SymmetricKeyRequest::SymmetricKeyRequest(const ClientId& clientId, 
                                         const ServerId& serverId,
                                         const uint64_t& nonce):
	Request(clientId, 1027)
{
	m_payloadSize = static_cast<uint32_t>(serverId.size()) + sizeof(uint64_t);
	m_payload.insert(m_payload.end(), serverId.begin(), serverId.end());

	for (size_t i = 0; i < sizeof(uint64_t); ++i)
	{
		auto byte = static_cast<uint8_t>((nonce >> (i * 8)) & 0xFF);
		m_payload.push_back(byte);
	}
}



ClientPublicKeyRequest::ClientPublicKeyRequest(const std::string& username, const ClientId& clientId, const std::string& publicKey)
	: Request(clientId, 1026)
{
	std::string paddedUsername = username;
	paddedUsername.insert(paddedUsername.end(), 255 - paddedUsername.size(), '\0');

	m_payloadSize = static_cast<uint32_t>(paddedUsername.size()) + static_cast<uint32_t>(publicKey.size());
	m_payload.insert(m_payload.end(), paddedUsername.begin(), paddedUsername.end());
	m_payload.insert(m_payload.end(), publicKey.begin(), publicKey.end());
}

ReconnectRequest::ReconnectRequest(const std::string& username, const ClientId& clientId)
	: Request(clientId, 1027)
{
	std::string paddedUsername = username;
	paddedUsername.insert(paddedUsername.end(), USERNAME_FIELD_SIZE - paddedUsername.size(), '\0');

	m_payloadSize = static_cast<uint32_t>(paddedUsername.size());
	m_payload.insert(m_payload.end(), paddedUsername.begin(), paddedUsername.end());
}

SendFileRequest::SendFileRequest(const std::string& fileName, const ClientId& clientId, const Buffer& messageContent)
	: Request(clientId, 1028)
{
	const auto contentSize = static_cast<uint32_t>(messageContent.size());

	std::string paddedFileName = fileName;
	paddedFileName.insert(paddedFileName.end(), FILENAME_FIELD_SIZE - paddedFileName.size(), '\0');

	m_payloadSize = sizeof(contentSize) + static_cast<uint32_t>(paddedFileName.size()) + static_cast<uint32_t>(messageContent.size());
		
	for (size_t i = 0; i < sizeof(uint32_t); ++i)
	{
		auto byte = static_cast<uint8_t>((contentSize >> (i * 8)) & 0xFF);
		m_payload.push_back(byte);
	}
	m_payload.insert(m_payload.end(), paddedFileName.begin(), paddedFileName.end());
	m_payload.insert(m_payload.end(), messageContent.begin(), messageContent.end());
}

CrcRequest::CrcRequest(const std::string& fileName, const ClientId& clientId, uint16_t code)
	: Request(clientId, code)
{
	std::string paddedFileName = fileName;
	paddedFileName.insert(paddedFileName.end(), FILENAME_FIELD_SIZE - paddedFileName.size(), '\0');

	m_payloadSize = static_cast<uint32_t>(paddedFileName.size());
	m_payload.insert(m_payload.end(), paddedFileName.begin(), paddedFileName.end());
}

ValidCrcRequest::ValidCrcRequest(const std::string& fileName, const ClientId& clientId)
	: CrcRequest(fileName, clientId, 1029)
{
}

InvalidCrcRequest::InvalidCrcRequest(const std::string& fileName, const ClientId& clientId)
	: CrcRequest(fileName, clientId, 1030)
{
}

LastInvalidCrcRequest::LastInvalidCrcRequest(const std::string& fileName, const ClientId& clientId)
	: CrcRequest(fileName, clientId, 1031)
{
}
