#include "AesWrapper.h"

#include <modes.h>
#include <aes.h>
#include <filters.h>

#include <stdexcept>
#include <immintrin.h>	// _rdrand32_step
#include <osrng.h>


unsigned char* AesWrapper::generateKey(unsigned char* buffer, uint32_t length)
{
	for (size_t i = 0; i < length; i += sizeof(unsigned int))
		_rdrand32_step(reinterpret_cast<unsigned int*>(&buffer[i]));
	return buffer;
}

AesWrapper::AesWrapper()
	: m_key{}
{
	generateKey(m_key, DEFAULT_KEY_LENGTH);
}

AesWrapper::AesWrapper(const unsigned char* key, uint32_t size)
	: m_key{}
{
	if (size != DEFAULT_KEY_LENGTH)
		throw std::length_error("key size must be 32 bytes");
	memcpy_s(m_key, DEFAULT_KEY_LENGTH, key, size);
}

AesWrapper::AesWrapper(const std::string& key)
	: AesWrapper(reinterpret_cast<const unsigned char*>(key.data()), static_cast<uint32_t>(key.size()))
{
}

const unsigned char* AesWrapper::getKey() const
{
	return m_key;
}

std::pair<std::string, std::string> AesWrapper::encrypt(const char* plain, uint32_t length)
{
	//CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = {0};
	// Generate a random IV
	CryptoPP::AutoSeededRandomPool prng;
	CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
	prng.GenerateBlock(iv, sizeof(iv));

	CryptoPP::AES::Encryption aesEncryption(m_key, DEFAULT_KEY_LENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

	std::string cipher;
	CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(cipher));
	stfEncryptor.Put(reinterpret_cast<const CryptoPP::byte*>(plain), length);
	stfEncryptor.MessageEnd();

	std::string ivString(reinterpret_cast<const char*>(iv), CryptoPP::AES::BLOCKSIZE);

	return std::make_pair(cipher, ivString);
}

std::string AesWrapper::decrypt(const char* cipher, uint32_t length, const std::string& ivString)
{
	CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
	std::memcpy(iv, ivString.data(), CryptoPP::AES::BLOCKSIZE);

	CryptoPP::AES::Decryption aesDecryption(m_key, DEFAULT_KEY_LENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

	std::string decrypted;
	CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decrypted));
	stfDecryptor.Put(reinterpret_cast<const CryptoPP::byte*>(cipher), length);
	stfDecryptor.MessageEnd();

	return decrypted;
}
