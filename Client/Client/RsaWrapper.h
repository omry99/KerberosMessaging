#pragma once

#include "osrng.h"
#include "rsa.h"

#include <string>

class RsaPublicWrapper
{
public:
	static const unsigned int KEYSIZE = 160;
	static const unsigned int BITS = 1024;

private:
	CryptoPP::AutoSeededRandomPool _rng;
	CryptoPP::RSA::PublicKey _publicKey;

	RsaPublicWrapper(const RsaPublicWrapper& rsaPublic);
	RsaPublicWrapper& operator=(const RsaPublicWrapper& rsaPublic);

public:
	RsaPublicWrapper(const char* key, unsigned int length);
	RsaPublicWrapper(const std::string& key);
	~RsaPublicWrapper() = default;

	std::string getPublicKey() const;
	char* getPublicKey(char* keyOut, unsigned int length) const;

	std::string encrypt(const std::string& plain);
	std::string encrypt(const char* plain, unsigned int length);
};


class RsaPrivateWrapper
{
public:
	static const unsigned int BITS = 1024;

private:
	CryptoPP::AutoSeededRandomPool _rng;
	CryptoPP::RSA::PrivateKey _privateKey;

	RsaPrivateWrapper(const RsaPrivateWrapper& rsaPrivate);
	RsaPrivateWrapper& operator=(const RsaPrivateWrapper& rsaPrivate);

public:
	RsaPrivateWrapper();
	RsaPrivateWrapper(const char* key, unsigned int length);
	explicit RsaPrivateWrapper(const std::string& key);
	~RsaPrivateWrapper();

	std::string getPrivateKey() const;
	char* getPrivateKey(char* keyOut, unsigned int length) const;

	std::string getPublicKey() const;
	char* getPublicKey(char* keyOut, unsigned int length) const;

	std::string decrypt(const std::string& cipher);
	std::string decrypt(const char* cipher, unsigned int length);
};
