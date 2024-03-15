#include <sha.h>
#include <hex.h>

std::string calculateSha256Hash(const std::string& inputString)
{
	CryptoPP::byte digest[CryptoPP::SHA256::DIGESTSIZE];
	CryptoPP::SHA256().CalculateDigest(digest, reinterpret_cast<const CryptoPP::byte*>(inputString.c_str()), inputString.length());

	std::string outputString(reinterpret_cast<const char*>(digest), CryptoPP::SHA256::DIGESTSIZE);

	return outputString;
}
