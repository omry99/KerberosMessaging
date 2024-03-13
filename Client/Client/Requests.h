#pragma once

#include "Defs.h"
#include "AesWrapper.h"
#include "TimeUtils.h"

#include <string>
#include <cstdint>

constexpr int USERNAME_FIELD_SIZE = 255;
constexpr int PASSWORD_FIELD_SIZE = 255;
constexpr int FILENAME_FIELD_SIZE = 255;

class Request
{
public:
	[[nodiscard]] Buffer serialize() const;

protected:
	Request(const ClientId& clientId, uint16_t code);

	ClientId m_clientId;
	uint8_t m_version = 24;
	uint16_t m_code;
	uint32_t m_payloadSize;
	Buffer m_payload;
};

// requests to Authentication Server

class RegistrationRequest : public Request
{
public:
	explicit RegistrationRequest(const std::string& username,
	                             const std::string& password);
};

class SymmetricKeyRequest : public Request
{
public:
	explicit SymmetricKeyRequest(const ClientId& clientId,
	                             const ServerId& serverId,
	                             const uint64_t& nonce);
};

// requests to Messaging Server

class Authenticator
{
public:
	Authenticator(const std::string& aesKey, const ClientId& clientId, const ServerId& serverId)
		: m_version(static_cast<std::byte>(24)),
		  m_clientId(clientId),
		  m_serverId(serverId),
		  m_creationTime(getCurrentTimestamp())
	{
		std::string toEncrypt;
		toEncrypt += static_cast<char>(m_version);
		toEncrypt += std::string(reinterpret_cast<char*>(m_clientId.data()), m_clientId.size());
		toEncrypt += std::string(reinterpret_cast<char*>(m_serverId.data()), m_serverId.size());
		for (size_t i = 0; i < sizeof(m_creationTime); ++i)
		{
			auto byte = static_cast<uint8_t>((m_creationTime >> (i * 8)) & 0xFF);
			toEncrypt += static_cast<char>(byte);
		}

		AesWrapper aesWrapper(aesKey);

		auto [encrypted, authenticatorIv] = aesWrapper.encrypt(toEncrypt.data(), static_cast<uint32_t>(toEncrypt.size()));
		m_encrypted = encrypted;
		m_authenticatorIv = authenticatorIv;
	}

	[[nodiscard]] size_t size() const
	{
		return m_authenticatorIv.size() + m_encrypted.size();
	}

	[[nodiscard]] std::string get() const
	{
		std::string out;
		out += m_authenticatorIv;
		out += m_encrypted;

		return out;
	}

private:
	std::string m_authenticatorIv;
	std::byte m_version;
	ClientId m_clientId;
	ServerId m_serverId;
	int64_t m_creationTime;

	std::string m_encrypted;
};

class SendSymmetricKeyRequest : public Request
{
public:
	explicit SendSymmetricKeyRequest(const ClientId& clientId,
	                                 const Authenticator& authenticator,
	                                 const std::string& ticket);
};

class SendMessageRequest : public Request
{
public:
	explicit SendMessageRequest(const ClientId& clientId,
	                            uint32_t msgSize,
	                            const std::string& msgIv,
	                            const std::string& msgContent);
};
