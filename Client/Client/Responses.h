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

class SymmetricKeyResponse : public NonEmptyResponse
{
public:
	SymmetricKeyResponse(const char* buffer, size_t bufferSize);

	explicit SymmetricKeyResponse(const Buffer& buffer);

	[[nodiscard]] static int getExpectedCode();

	[[nodiscard]] std::string getEncryptedKey() const;

	[[nodiscard]] std::string getTicket() const;

private:
	// TODO: Buffers?
	std::string m_encryptedKey;
	std::string m_ticket;
};

class ReceivedSymmetricKeyResponse : public Response
{
public:
	ReceivedSymmetricKeyResponse(const char* buffer, size_t bufferSize);

	explicit ReceivedSymmetricKeyResponse(const Buffer& buffer);

	[[nodiscard]] static int getExpectedCode();
};

class ReceivedMessageResponse : public Response
{
public:
	ReceivedMessageResponse(const char* buffer, size_t bufferSize);

	explicit ReceivedMessageResponse(const Buffer& buffer);

	[[nodiscard]] static int getExpectedCode();
};




// TODO: delete

class AcceptReconnectResponse final : public SymmetricKeyResponse
{
public:
	// Same c'tors
	using SymmetricKeyResponse::SymmetricKeyResponse;

	[[nodiscard]] static int getExpectedCode();
};

class RejectedReconnectResponse final : public NonEmptyResponse
{
public:
	// Same c'tors
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
