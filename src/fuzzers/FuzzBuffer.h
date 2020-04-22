#pragma once

#include <cstddef>

namespace zeek {

struct FuzzBuffer {

	static constexpr int PKT_MAGIC_LEN = 4;
	static constexpr unsigned char PKT_MAGIC[PKT_MAGIC_LEN + 1] = "\1PKT";

	FuzzBuffer(const unsigned char* data, size_t size)
		: begin(data), end(data + size)
		{ }

	bool Valid() const;

	int Next(const unsigned char** chunk, size_t* len, bool* is_orig);

	const unsigned char* begin;
	const unsigned char* end;
};

} // namespace zeek
