#pragma once

#include "Defs.h"
#include "AesWrapper.h"
#include "TimeUtils.h"

#include <string>
#include <cstdint>

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
