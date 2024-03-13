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

SendSymmetricKeyRequest::SendSymmetricKeyRequest(const ClientId& clientId, 
                                                 const Authenticator& authenticator,
                                                 const std::string& ticket) :
	Request(clientId, 1028)
{
	m_payloadSize = static_cast<uint32_t>(authenticator.size()) + static_cast<uint32_t>(ticket.size());
	std::string authenticatorBytes = authenticator.get();
	m_payload.insert(m_payload.end(), authenticatorBytes.begin(), authenticatorBytes.end());
	m_payload.insert(m_payload.end(), ticket.begin(), ticket.end());
}

SendMessageRequest::SendMessageRequest(const ClientId& clientId,
                                       uint32_t msgSize,
                                       const std::string& msgIv,
                                       const std::string& msgContent) :
	Request(clientId, 1029)
{
	m_payloadSize = static_cast<uint32_t>(clientId.size()) + sizeof(msgSize) + static_cast<uint32_t>(msgIv.size()) +
		static_cast<uint32_t>(msgContent.size());

	for (size_t i = 0; i < sizeof(msgSize); ++i)
	{
		auto byte = static_cast<uint8_t>((msgSize >> (i * 8)) & 0xFF);
		m_payload.push_back(byte);
	}

	m_payload.insert(m_payload.end(), msgIv.begin(), msgIv.end());
	m_payload.insert(m_payload.end(), msgContent.begin(), msgContent.end());
}
