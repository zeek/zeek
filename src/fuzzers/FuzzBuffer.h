#pragma once

#include <cstddef>

namespace zeek {

/**
 * This structure helps chunk/simulate protocol conversions from arbitrary
 * input strings (like those produced by fuzzing engines).  A fuzzing engine
 * passes in some input string, and we chunk it into originator/responder
 * messages according to any PKT_MAGIC delimiting bytestrings found in that
 * input (originator vs. responder is determined by inspecting low-bit of
 * the byte immediately following PKT_MAGIC and then the remaining bytes up
 * to the next PKT_MAGIC delimiter are considered to be the next buffer to
 * send along to an analyzers Deliver method.
 */
class FuzzBuffer {

	static constexpr int PKT_MAGIC_LEN = 4;
	static constexpr unsigned char PKT_MAGIC[PKT_MAGIC_LEN + 1] = "\1PKT";

	/**
	 * Initialize fuzz buffer.
	 * @param data  pointer to start of fuzzing buffer produced by fuzz engine.
	 * @param size  size of the fuzzing buffer pointed to by *data*.
	 */
	FuzzBuffer(const unsigned char* data, size_t size)
		: begin(data), end(data + size)
		{ }

	/**
	 * @return  whether the fuzz buffer object is valid --  has enough bytes
	 * to Deliver to an analyzer and starts with a *PKT_MAGIC* bytestring.
	 */
	bool Valid() const;

	/**
	 * Finds the next chunk of data to pass along to an analyzer.
	 * @param chunk  the data chunk to return
	 * @param len  the size of the chunk returned in *chunk*
	 * @param is_orig  whether returned chunk is from originator or responder
	 * @return  a value less than zero if a chunk could not be extracted
	 */
	int Next(const unsigned char** chunk, size_t* len, bool* is_orig);

private:

	const unsigned char* begin;
	const unsigned char* end;
};

} // namespace zeek
