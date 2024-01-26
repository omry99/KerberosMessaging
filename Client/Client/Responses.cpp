#include "Responses.h"

#include <iomanip>
#include <sstream>

uint16_t getResponseCode(const char* response)
{
	uint16_t code;
	std::memcpy(&code, response + sizeof(uint8_t), sizeof(code));

	return code;
}

Response::Response(const char* buffer, size_t bufferSize)
	: version(0), code(0), payloadSize(0)
{
	// Check if the buffer is large enough to hold the expected data
	if (bufferSize < sizeof(version) + sizeof(code) + sizeof(payloadSize))
	{
		throw std::runtime_error("Buffer too small to hold a response");
	}

	// Copy data from the buffer to the class members
	std::memcpy(&version, buffer, sizeof(version));
	std::memcpy(&code, buffer + sizeof(version), sizeof(code));
	std::memcpy(&payloadSize, buffer + sizeof(version) + sizeof(code), sizeof(payloadSize));

	// Calculate the payload offset
	constexpr size_t payloadOffset = sizeof(version) + sizeof(code) + sizeof(payloadSize);
	if (bufferSize >= payloadOffset + payloadSize)
	{
		payload.resize(payloadSize);
		std::memcpy(payload.data(), buffer + payloadOffset, payloadSize);
	}
	else
	{
		throw std::runtime_error("Buffer too small to hold the payload");
	}
}

ClientId NonEmptyResponse::getClientId() const
{
	return m_clientId;
}

NonEmptyResponse::NonEmptyResponse(const char* buffer, size_t bufferSize)
	: Response(buffer, bufferSize),
	  m_clientId()
{
	std::memcpy(m_clientId.data(), payload.data(), m_clientId.size());
}

NonEmptyResponse::NonEmptyResponse(const Buffer& buffer)
	: NonEmptyResponse(buffer.data(), buffer.size())
{
}

RegistrationSuccessResponse::RegistrationSuccessResponse(const char* buffer, size_t bufferSize)
	: NonEmptyResponse(buffer, bufferSize)
{
}

RegistrationSuccessResponse::RegistrationSuccessResponse(const Buffer& buffer)
	: RegistrationSuccessResponse(buffer.data(), buffer.size())
{
}

std::string RegistrationSuccessResponse::getClientIdAsAscii() const
{
	std::ostringstream oss;
	// Get the client ID in the expected format by looping through the array and formatting each byte as a 2-character hexadecimal
	for (const unsigned char i : m_clientId)
	{
		oss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(i);
	}

	return oss.str();
}

int RegistrationSuccessResponse::getExpectedCode()
{
	return 2100;
}

KeyResponse::KeyResponse(const char* buffer, size_t bufferSize): NonEmptyResponse(buffer, bufferSize)
{
	m_encryptedAesKey = std::string(payload.data() + m_clientId.size(), payloadSize - m_clientId.size());
}

KeyResponse::KeyResponse(const Buffer& buffer)
	: KeyResponse(buffer.data(), buffer.size())
{
}

int KeyResponse::getExpectedCode()
{
	return 2102;
}

std::string KeyResponse::getEncryptedAesKey() const
{
	return m_encryptedAesKey;
}

int AcceptReconnectResponse::getExpectedCode()
{
	return 2105;
}

int RejectedReconnectResponse::getExpectedCode()
{
	return 2106;
}

ReceivedFileResponse::ReceivedFileResponse(const char* buffer, size_t bufferSize)
	: NonEmptyResponse(buffer, bufferSize),
	  m_contentSize(0),
	  m_checksum(0)
{
	std::memcpy(m_clientId.data(), payload.data(), m_clientId.size());
	std::memcpy(&m_contentSize, payload.data() + m_clientId.size(), sizeof(m_contentSize));
	m_fileName = std::string(payload.data() + m_clientId.size() + sizeof m_contentSize, 255);
	std::memcpy(&m_checksum, payload.data() + m_clientId.size() + sizeof(m_contentSize) + m_fileName.size(), sizeof(m_checksum));
}

ReceivedFileResponse::ReceivedFileResponse(const Buffer& buffer): ReceivedFileResponse(buffer.data(), buffer.size())
{
}

int ReceivedFileResponse::getExpectedCode()
{
	return 2103;
}

uint32_t ReceivedFileResponse::getChecksum() const
{
	return m_checksum;
}
