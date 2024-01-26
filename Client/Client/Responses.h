#pragma once

#include "Defs.h"
#include "Macros.h"

#include <string>

uint16_t getResponseCode(const char* response);

class Response
{
protected:
	Response(const char* buffer, size_t bufferSize);

	DELETE_COPY(Response);
	DELETE_MOVE(Response);
	virtual ~Response() = default;

	uint8_t version;
	uint16_t code;
	uint32_t payloadSize;
	Buffer payload;
};

class NonEmptyResponse : public Response
{
public:
	[[nodiscard]] ClientId getClientId() const;

protected:
	NonEmptyResponse(const char* buffer, size_t bufferSize);

	explicit NonEmptyResponse(const Buffer& buffer);

	ClientId m_clientId;
};

class RegistrationSuccessResponse final : public NonEmptyResponse
{
public:
	RegistrationSuccessResponse(const char* buffer, size_t bufferSize);

	explicit RegistrationSuccessResponse(const Buffer& buffer);

	[[nodiscard]] std::string getClientIdAsAscii() const;

	[[nodiscard]] static int getExpectedCode();
};

class KeyResponse : public NonEmptyResponse
{
public:
	KeyResponse(const char* buffer, size_t bufferSize);

	explicit KeyResponse(const Buffer& buffer);

	[[nodiscard]] static int getExpectedCode();

	[[nodiscard]] std::string getEncryptedAesKey() const;

private:
	std::string m_encryptedAesKey;
};

class AcceptReconnectResponse final : public KeyResponse
{
public:
	// Some c'tors
	using KeyResponse::KeyResponse;

	[[nodiscard]] static int getExpectedCode();
};

class RejectedReconnectResponse final : public NonEmptyResponse
{
public:
	// Some c'tors
	using NonEmptyResponse::NonEmptyResponse;

	[[nodiscard]] static int getExpectedCode();
};

class ReceivedFileResponse final : public NonEmptyResponse
{
public:
	ReceivedFileResponse(const char* buffer, size_t bufferSize);

	explicit ReceivedFileResponse(const Buffer& buffer);

	[[nodiscard]] static int getExpectedCode();

	[[nodiscard]] uint32_t getChecksum() const;

private:
	uint32_t m_contentSize;
	std::string m_fileName;
	uint32_t m_checksum;
};
