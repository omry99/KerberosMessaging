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
	return 1600;
}

SymmetricKeyResponse::SymmetricKeyResponse(const char* buffer, size_t bufferSize)
	: NonEmptyResponse(buffer, bufferSize)
{
	// TODO: const
	m_encryptedKey = std::string(payload.data() + m_clientId.size(), 80);
	m_ticket = std::string(payload.data() + m_clientId.size() + m_encryptedKey.size(), payloadSize - m_clientId.size() - m_encryptedKey.size());
}

SymmetricKeyResponse::SymmetricKeyResponse(const Buffer& buffer)
	: SymmetricKeyResponse(buffer.data(), buffer.size())
{
}

int SymmetricKeyResponse::getExpectedCode()
{
	return 1603;
}

std::string SymmetricKeyResponse::getEncryptedKey() const
{
	return m_encryptedKey;
}

std::string SymmetricKeyResponse::getTicket() const
{
	return m_ticket;
}


ReceivedSymmetricKeyResponse::ReceivedSymmetricKeyResponse(const char* buffer, size_t bufferSize)
	: Response(buffer, bufferSize)
{
}

ReceivedSymmetricKeyResponse::ReceivedSymmetricKeyResponse(const Buffer& buffer)
	: ReceivedSymmetricKeyResponse(buffer.data(), buffer.size())
{
}

int ReceivedSymmetricKeyResponse::getExpectedCode()
{
	return 1604;
}


ReceivedMessageResponse::ReceivedMessageResponse(const char* buffer, size_t bufferSize)
	: Response(buffer, bufferSize)
{
}

ReceivedMessageResponse::ReceivedMessageResponse(const Buffer& buffer)
	: ReceivedMessageResponse(buffer.data(), buffer.size())
{
}

int ReceivedMessageResponse::getExpectedCode()
{
	return 1605;
}
