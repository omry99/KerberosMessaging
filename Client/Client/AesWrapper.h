#pragma once

#include "Macros.h"

#include <cstdint>
#include <string>

class AesWrapper
{
public:
	static constexpr uint32_t DEFAULT_KEY_LENGTH = 32;

	AesWrapper();
	AesWrapper(const unsigned char* key, uint32_t size);
	explicit AesWrapper(const std::string& key);

	DELETE_COPY(AesWrapper);

	DELETE_MOVE(AesWrapper);

	~AesWrapper() = default;

	[[nodiscard]] const unsigned char* getKey() const;
	static unsigned char* generateKey(unsigned char* buffer, uint32_t length);

	[[nodiscard]] std::pair<std::string, std::string> encrypt(const char* plain, uint32_t length);
	[[nodiscard]] std::string decrypt(const char* cipher, uint32_t length, const std::string& ivString);

private:
	unsigned char m_key[DEFAULT_KEY_LENGTH];
};