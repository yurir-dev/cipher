
#include "cipher/cipher1to2.h"

#include <type_traits>
#include <iostream>
#include <vector>
#include <array>
#include <set>

int test(const uint8_t* plaintext, size_t plaintextLen, const std::string_view& key)
{
	std::vector<uint8_t> ciphertext; ciphertext.resize(plaintextLen * 2);
	size_t cipherTextLen{ 0 };

	auto hashFunc = [](std::vector<uint8_t> const& vec) -> size_t {
		std::size_t seed = vec.size();
		for (auto& i : vec) {
			seed ^= i + 0x9e3779b9 + (seed << 6) + (seed >> 2);
		}
		return seed;
	};

	// repeat for the same key, same plaintext
	// cipher should be different every time
	std::set<size_t> cipherHashes;
	for (size_t i = 0; i < 100; ++i)
	{
		{
			cipher::cipher1to2 cipher{ key };
			cipher.encipher(plaintext, plaintextLen, ciphertext.data(), cipherTextLen);

			if (cipherTextLen != ciphertext.size())
			{
				std::cout << "plain texts sizes don't match: " << cipherTextLen << " != " << ciphertext.size() << std::endl;
				return __LINE__;
			}

			const std::size_t hash{ hashFunc(ciphertext) };
			if (cipherHashes.end() != cipherHashes.find(hash))
			{
				std::cout << "cipher hash found:" << cipherHashes.size() << std::endl;
				return __LINE__;
			}
			cipherHashes.emplace(hash);
		}

		std::vector<uint8_t> plaintext2;
		plaintext2.resize(cipherTextLen / 2);
		{
			cipher::cipher1to2 cipher{ key };
			size_t newPlaintextLen{ 0 };
			cipher.decipher(ciphertext.data(), cipherTextLen, plaintext2.data(), newPlaintextLen);

			if (newPlaintextLen != plaintext2.size())
			{
				std::cout << "plain texts sizes don't match: " << newPlaintextLen << " != " << plaintext2.size() << std::endl;
				return __LINE__;
			}
		}

		if (plaintextLen != plaintext2.size())
		{
			std::cout << "plain text sizes don't match" << std::endl;
			return __LINE__;
		}
		for (size_t j = 0; j < plaintextLen; ++j)
		{
			if (plaintext[j] != plaintext2[j])
			{
				std::cout << "plain texts don't match" << std::endl;
				return __LINE__;
			}
		}
	}
	std::cout << "success plain texts match" << std::endl;
	return 0;
}
int main(int /*argc*/, char* /*argv*/[])
{
	std::string plaintextAscii{
	"42 is a 2013 American biographical sports film about baseball player Jackie Robinson,"
	"the first black athlete to play in Major League Baseball (MLB) during the modern era."
	"Written and directed by Brian Helgeland, the film stars Chadwick Boseman as Robinson,"
	"alongside Harrison Ford, Nicole Beharie, Christopher Meloni, André Holland, Lucas Black,"
	"Hamish Linklater and Ryan Merriman in supporting roles.[4] The title of the film is a"
	"reference to Robinson's jersey number, which was universally retired across all MLB teams in 1997."
	"The project was announced in June 2011, with principal photography taking place in Macon,"
	"Georgiaand Atlanta Film Studios Paulding County in Hiram as well as in Alabamaand Chattanooga, Tennessee.[5]"
	"42 was theatrically released in the United States on April 12, 2013."
	"[6] The film received generally positive reviews from critics, who praised the performances"
	"of Bosemanand Ford,and it grossed $97.5 million on a production budget of $31–40 million." };

	if (int res = test(reinterpret_cast<uint8_t*>(plaintextAscii.data()), plaintextAscii.length(), "key1") != 0)
		return res;

	std::vector<uint8_t> plaintextBin;
	for (size_t i = 0; i < 1000; ++i)
	{
		plaintextBin.push_back(static_cast<uint8_t>(i));
	}

	if (int res = test(plaintextBin.data(), plaintextBin.size(), "key2") != 0)
		return res;

	return 0;
}