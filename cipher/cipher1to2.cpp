#include "cipher1to2.h"

#include <array>
#include <random>
#include <algorithm>

using namespace cipher;


struct cipher1to2::impl
{
	std::array<std::array<uint16_t, 256>, 256> _plain2cipher;
	std::array<uint8_t, 256 * 256> _cipher2plain;
};

cipher1to2::cipher1to2(const std::string_view& key)
	:_impl{std::make_unique<impl>()}
{
	std::vector<uint16_t> vals2bytes;
	vals2bytes.resize(256 * 256);
	for (size_t i = 0 ; i < vals2bytes.size() ; ++i)
		vals2bytes[i] = static_cast<uint16_t>(i);

	const std::size_t hash{ std::hash<std::string_view>{}(key) };
	std::seed_seq seed{hash};
	std::mt19937 gen(seed);
	std::shuffle(vals2bytes.begin(), vals2bytes.end(), gen);

	for (size_t i = 0; i < 256; ++i)
	{
		for (size_t j = 0; j < 256; ++j)
		{
			const auto val{ vals2bytes[i * 256 + j] };
			_impl->_plain2cipher[i][j] = val;
			_impl->_cipher2plain[val] = static_cast<uint8_t>(i);
		}
	}
}
cipher1to2::~cipher1to2() = default;

static uint8_t xor4bytes(const uint32_t val)
{
	const uint8_t* ptr{reinterpret_cast<const uint8_t*>(&val)};
	return ptr[0] ^ ptr[1] ^ ptr[2] ^ ptr[3];
}
void cipher1to2::encipher(const uint8_t* plaintext, size_t lenPlain, uint8_t* ciphertext, size_t& ciphertextLen)const noexcept
{
	uint16_t* cipherPtr{ reinterpret_cast<uint16_t*>(ciphertext) };

	for (size_t i = 0; i < lenPlain; ++i)
	{
		std::random_device rd;
		std::mt19937 gen(rd());
		const uint8_t randIndex{xor4bytes(gen())};

		cipherPtr[i] = _impl->_plain2cipher[plaintext[i]][randIndex];
	}
	ciphertextLen = lenPlain * 2;
}
void cipher1to2::decipher(const uint8_t* ciphertext, size_t lenCipher, uint8_t* plaintext, size_t& plaintextLen)const noexcept
{
	const uint16_t* cipherPtr{ reinterpret_cast<const uint16_t*>(ciphertext) };

	for (size_t i = 0; i < lenCipher / 2; ++i)
	{
		plaintext[i] = _impl->_cipher2plain[cipherPtr[i]];
	}
	plaintextLen = lenCipher / 2;
}
