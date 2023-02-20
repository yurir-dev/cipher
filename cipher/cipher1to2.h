#pragma once

#include <memory>
#include <string_view>

namespace cipher
{
	/*
		1) a homophonic substitution cipher with 64 bits key (the string_view key is hashed to size_t)
		2) every plaintext byte becames 2 bytes in ciphertext.
		   for every plaintext value in [0, 255] the cipher value is a randomly chosen from assigned 256 values in the range of [0, 256*256]
		   each plaintext byte has a unique group of 256 bytes in the range of [0, 256*256], these possible 256 values are defined by the key.
	*/

	class cipher1to2
	{
	public:
		cipher1to2(const std::string_view& key);
		~cipher1to2();

		void encipher(const uint8_t* plaintext, size_t lenPlain, uint8_t* ciphertext, size_t& ciphertextLen)const noexcept;
		void decipher(const uint8_t* ciphertext, size_t lenCipher, uint8_t* plaintext, size_t& plaintextLen)const noexcept;

	private:
		struct impl;
		std::unique_ptr<impl> _impl;
	};

};