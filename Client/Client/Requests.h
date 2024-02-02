#pragma once

#include "Defs.h"

#include <string>

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



class ClientPublicKeyRequest : public Request
{
public:
	ClientPublicKeyRequest(const std::string& username, const ClientId& clientId, const std::string& publicKey);
};

class ReconnectRequest : public Request
{
public:
	explicit ReconnectRequest(const std::string& username, const ClientId& clientId);
};

class SendFileRequest : public Request
{
public:
	SendFileRequest(const std::string& fileName, const ClientId& clientId, const Buffer& messageContent);
};

class CrcRequest : public Request
{
protected:
	CrcRequest(const std::string& fileName, const ClientId& clientId, uint16_t code);
};

class ValidCrcRequest : public CrcRequest
{
public:
	ValidCrcRequest(const std::string& fileName, const ClientId& clientId);
};

class InvalidCrcRequest : public CrcRequest
{
public:
	InvalidCrcRequest(const std::string& fileName, const ClientId& clientId);
};

class LastInvalidCrcRequest : public CrcRequest
{
public:
	LastInvalidCrcRequest(const std::string& fileName, const ClientId& clientId);
};
