#pragma once

#include <cstddef>
#include <memory>
#include <optional>

namespace zeek { namespace detail {

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
public:

	struct Chunk {
		std::unique_ptr<unsigned char[]> data;
		size_t size;
		bool is_orig;
	};

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
	 * @return  the number of chunks in the fuzz buffer object
	 */
	int ChunkCount() const;

	/**
	 * @return  the next chunk to deliver, if one could be extracted
	 */
	std::optional<Chunk> Next();

private:

	const unsigned char* begin;
	const unsigned char* end;
};

}} // namespace zeek::detail
