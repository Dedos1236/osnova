#include "sm3.h"
#include <cstring>
#include <bit>

namespace nit::crypto::osnova {

namespace {

	inline uint32_t bswap_32(uint32_t x) {
		return (x >> 24) | ((x >> 8) & 0x0000FF00) | ((x << 8) & 0x00FF0000) | (x << 24);
	}

	inline uint64_t bswap_64(uint64_t x) {
		return (x >> 56) |
			   ((x & 0x00FF000000000000ull) >> 40) |
			   ((x & 0x0000FF0000000000ull) >> 24) |
			   ((x & 0x000000FF00000000ull) >> 8) |
			   ((x & 0x00000000FF000000ull) << 8) |
			   ((x & 0x0000000000FF0000ull) << 24) |
			   ((x & 0x000000000000FF00ull) << 40) |
			   (x << 56);
	}

	inline uint32_t rotl32(uint32_t x, int n) {
		return (x << n) | (x >> (32 - n));
	}

	inline uint32_t sm3_p0(uint32_t x) {
		return x ^ rotl32(x, 9) ^ rotl32(x, 17);
	}

	inline uint32_t sm3_p1(uint32_t x) {
		return x ^ rotl32(x, 15) ^ rotl32(x, 23);
	}

	inline uint32_t sm3_ff0(uint32_t x, uint32_t y, uint32_t z) {
		return x ^ y ^ z;
	}

	inline uint32_t sm3_ff1(uint32_t x, uint32_t y, uint32_t z) {
		return (x & y) | (x & z) | (y & z);
	}

	inline uint32_t sm3_gg0(uint32_t x, uint32_t y, uint32_t z) {
		return x ^ y ^ z;
	}

	inline uint32_t sm3_gg1(uint32_t x, uint32_t y, uint32_t z) {
		return (x & y) | (~x & z);
	}

	const uint32_t SM3_IV[8] = {
		0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
		0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
	};

	const uint32_t SM3_T[64] = {
		0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
		0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
		0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
		0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
		0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
		0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
		0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
		0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A 
	};
}

Sm3::Sm3() noexcept : bit_count_(0), buffer_len_(0) {
	for(int i=0; i<8; i++) state_[i] = SM3_IV[i];
}

void Sm3::transform() noexcept {
	uint32_t W[68];
	uint32_t W1[64];

	for (int i = 0; i < 16; i++) {
		std::memcpy(&W[i], buffer_ + i * 4, 4);
		if constexpr (std::endian::native == std::endian::little) {
			W[i] = bswap_32(W[i]);
		}
	}

	for (int i = 16; i < 68; i++) {
		uint32_t temp = W[i - 16] ^ W[i - 9] ^ rotl32(W[i - 3], 15);
		W[i] = sm3_p1(temp) ^ rotl32(W[i - 13], 7) ^ W[i - 6];
	}

	for (int i = 0; i < 64; i++) {
		W1[i] = W[i] ^ W[i + 4];
	}

	uint32_t A = state_[0];
	uint32_t B = state_[1];
	uint32_t C = state_[2];
	uint32_t D = state_[3];
	uint32_t E = state_[4];
	uint32_t F = state_[5];
	uint32_t G = state_[6];
	uint32_t H = state_[7];

	for (int i = 0; i < 16; i++) {
		uint32_t SS1 = rotl32(rotl32(A, 12) + E + rotl32(0x79CC4519, i), 7);
		uint32_t SS2 = SS1 ^ rotl32(A, 12);
		uint32_t TT1 = sm3_ff0(A, B, C) + D + SS2 + W1[i];
		uint32_t TT2 = sm3_gg0(E, F, G) + H + SS1 + W[i];
		D = C;
		C = rotl32(B, 9);
		B = A;
		A = TT1;
		H = G;
		G = rotl32(F, 19);
		F = E;
		E = sm3_p0(TT2);
	}

	for (int i = 16; i < 64; i++) {
		// T_j optimization
		uint32_t TT = (i < 64) ? 0x7A879D8A : 0;
		uint32_t SS1 = rotl32(rotl32(A, 12) + E + rotl32(TT, i % 32), 7);
		uint32_t SS2 = SS1 ^ rotl32(A, 12);
		uint32_t TT1 = sm3_ff1(A, B, C) + D + SS2 + W1[i];
		uint32_t TT2 = sm3_gg1(E, F, G) + H + SS1 + W[i];
		D = C;
		C = rotl32(B, 9);
		B = A;
		A = TT1;
		H = G;
		G = rotl32(F, 19);
		F = E;
		E = sm3_p0(TT2);
	}

	state_[0] ^= A;
	state_[1] ^= B;
	state_[2] ^= C;
	state_[3] ^= D;
	state_[4] ^= E;
	state_[5] ^= F;
	state_[6] ^= G;
	state_[7] ^= H;
}

void Sm3::update(std::span<const uint8_t> data) noexcept {
	size_t len = data.size();
	size_t in_offset = 0;

	while (len > 0) {
		size_t to_copy = std::min(BLOCK_SIZE - buffer_len_, len);
		std::memcpy(buffer_ + buffer_len_, data.data() + in_offset, to_copy);
		
		buffer_len_ += to_copy;
		in_offset += to_copy;
		len -= to_copy;
		bit_count_ += to_copy * 8;

		if (buffer_len_ == BLOCK_SIZE) {
			transform();
			buffer_len_ = 0;
		}
	}
}

void Sm3::finalize(std::span<uint8_t, DIGEST_SIZE> out) noexcept {
	uint64_t total_bits = bit_count_;
	
	buffer_[buffer_len_++] = 0x80;
	
	if (buffer_len_ > 56) {
		std::memset(buffer_ + buffer_len_, 0, BLOCK_SIZE - buffer_len_);
		transform();
		buffer_len_ = 0;
	}
	
	std::memset(buffer_ + buffer_len_, 0, 56 - buffer_len_);
	
	if constexpr (std::endian::native == std::endian::little) {
		total_bits = bswap_64(total_bits);
	}
	std::memcpy(buffer_ + 56, &total_bits, 8);
	
	transform();

	for (int i = 0; i < 8; i++) {
		uint32_t val = state_[i];
		if constexpr (std::endian::native == std::endian::little) {
			val = bswap_32(val);
		}
		std::memcpy(out.data() + (i * 4), &val, 4);
	}
	
	// Clean
	std::memset(this, 0, sizeof(*this));
}

void Sm3::compute(std::span<uint8_t, DIGEST_SIZE> out, std::span<const uint8_t> data) noexcept {
	Sm3 sm3;
	sm3.update(data);
	sm3.finalize(out);
}

} // namespace nit::crypto::osnova
