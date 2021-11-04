#pragma once

#include <cstddef>
#include <memory>
#include <optional>

namespace zeek::detail
	{

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
class FuzzBuffer
	{
public:
	struct Chunk
		{
		std::unique_ptr<unsigned char[]> data;
		size_t size;
		bool is_orig;
		};

	static constexpr int PKT_MAGIC_LEN = 4;
	static constexpr unsigned char PKT_MAGIC[PKT_MAGIC_LEN + 1] = "\1PKT";
	static constexpr int MAX_CHUNK_COUNT = 64;

	/**
	 * Initialize fuzz buffer.
	 * @param data  pointer to start of fuzzing buffer produced by fuzz engine.
	 * @param size  size of the fuzzing buffer pointed to by *data*.
	 */
	FuzzBuffer(const unsigned char* data, size_t size) : begin(data), end(data + size) { }

	/**
	 * @return  whether the fuzz buffer object is valid --  has enough bytes
	 * to Deliver to an analyzer, starts with a *PKT_MAGIC* bytestring, and
	 * contains less than the limiting number of chunk.
	 * .
	 */
	bool Valid(int chunk_count_limit = MAX_CHUNK_COUNT) const;

	/**
	 * @param chunk_count_limit  Number of chunks to stop counting at (zero
	 * means "never stop").
	 * @return  the number of chunks in the fuzz buffer object
	 */
	int ChunkCount(int chunk_count_limit = 0) const;

	/**
	 * @param  Maximum number of chunks to permit the FuzzBuffer to have.
	 * @return  Whether the FuzzBuffer exceeds the desired chunk count limit.
	 */
	bool ExceedsChunkLimit(int chunk_count_limit) const
		{
		return ChunkCount(chunk_count_limit + 1) > chunk_count_limit;
		}

	/**
	 * @return  the next chunk to deliver, if one could be extracted
	 */
	std::optional<Chunk> Next();

private:
	const unsigned char* begin;
	const unsigned char* end;
	};

	} // namespace zeek::detail
