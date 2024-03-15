#pragma once

#include "Defs.h"
#include "AesWrapper.h"
#include "TimeUtils.h"
#include "Authenticator.h"

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
