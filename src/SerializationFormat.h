// Implements different data formats for serialization.

#pragma once

#include "zeek-config.h"

#include <stdint.h>
#include <string>

ZEEK_FORWARD_DECLARE_NAMESPACED(IPAddr, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(IPPrefix, zeek);

struct in_addr;
struct in6_addr;

namespace zeek::detail {

// Abstract base class.
class SerializationFormat {
public:
	SerializationFormat();
	virtual ~SerializationFormat();

	// Unserialization.
	virtual void StartRead(const char* data, uint32_t len);
	virtual void EndRead();

	virtual bool Read(int* v, const char* tag) = 0;
	virtual bool Read(uint16_t* v, const char* tag) = 0;
	virtual bool Read(uint32_t* v, const char* tag) = 0;
	virtual bool Read(int64_t* v, const char* tag) = 0;
	virtual bool Read(uint64_t* v, const char* tag) = 0;
	virtual bool Read(char* v, const char* tag) = 0;
	virtual bool Read(bool* v, const char* tag) = 0;
	virtual bool Read(double* d, const char* tag) = 0;
	virtual bool Read(std::string* s, const char* tag) = 0;
	virtual bool Read(IPAddr* addr, const char* tag) = 0;
	virtual bool Read(IPPrefix* prefix, const char* tag) = 0;
	virtual bool Read(in_addr* addr, const char* tag) = 0;
	virtual bool Read(in6_addr* addr, const char* tag) = 0;

	// Returns number of raw bytes read since last call to StartRead().
	int BytesRead() const	{ return bytes_read; }

	// Passes ownership of string.
	virtual bool Read(char** str, int* len, const char* tag) = 0;

	// Serialization.
	virtual void StartWrite();

	/**
	 * Retrieves serialized data.
	 * @param data A pointer that will be assigned to point at the internal
	 *             buffer containing serialized data.  The memory should
	 *             be reclaimed using "free()".
	 * @return The number of bytes in the buffer object assigned to \a data.
	 */
	virtual uint32_t EndWrite(char** data);

	virtual bool Write(int v, const char* tag) = 0;
	virtual bool Write(uint16_t v, const char* tag) = 0;
	virtual bool Write(uint32_t v, const char* tag) = 0;
	virtual bool Write(int64_t v, const char* tag) = 0;
	virtual bool Write(uint64_t v, const char* tag) = 0;
	virtual bool Write(char v, const char* tag) = 0;
	virtual bool Write(bool v, const char* tag) = 0;
	virtual bool Write(double d, const char* tag) = 0;
	virtual bool Write(const char* s, const char* tag) = 0;
	virtual bool Write(const char* buf, int len, const char* tag) = 0;
	virtual bool Write(const std::string& s, const char* tag) = 0;
	virtual bool Write(const IPAddr& addr, const char* tag) = 0;
	virtual bool Write(const IPPrefix& prefix, const char* tag) = 0;
	virtual bool Write(const in_addr& addr, const char* tag) = 0;
	virtual bool Write(const in6_addr& addr, const char* tag) = 0;

	virtual bool WriteOpenTag(const char* tag) = 0;
	virtual bool WriteCloseTag(const char* tag) = 0;
	virtual bool WriteSeparator() = 0;

	// Returns number of raw bytes written since last call to StartWrite().
	int BytesWritten() const	{ return bytes_written; }

protected:
	bool ReadData(void* buf, size_t count);
	bool WriteData(const void* buf, size_t count);

	static const uint32_t INITIAL_SIZE = 65536;
	static const float GROWTH_FACTOR;
	char* output;
	uint32_t output_size;
	uint32_t output_pos;

	const char* input;
	uint32_t input_len;
	uint32_t input_pos;

	int bytes_written;
	int bytes_read;
};

class BinarySerializationFormat final : public SerializationFormat {
public:
	BinarySerializationFormat();
	~BinarySerializationFormat() override;

	bool Read(int* v, const char* tag) override;
	bool Read(uint16_t* v, const char* tag) override;
	bool Read(uint32_t* v, const char* tag) override;
	bool Read(int64_t* v, const char* tag) override;
	bool Read(uint64_t* v, const char* tag) override;
	bool Read(char* v, const char* tag) override;
	bool Read(bool* v, const char* tag) override;
	bool Read(double* d, const char* tag) override;
	bool Read(char** str, int* len, const char* tag) override;
	bool Read(std::string* s, const char* tag) override;
	bool Read(IPAddr* addr, const char* tag) override;
	bool Read(IPPrefix* prefix, const char* tag) override;
	bool Read(in_addr* addr, const char* tag) override;
	bool Read(in6_addr* addr, const char* tag) override;
	bool Write(int v, const char* tag) override;
	bool Write(uint16_t v, const char* tag) override;
	bool Write(uint32_t v, const char* tag) override;
	bool Write(int64_t v, const char* tag) override;
	bool Write(uint64_t v, const char* tag) override;
	bool Write(char v, const char* tag) override;
	bool Write(bool v, const char* tag) override;
	bool Write(double d, const char* tag) override;
	bool Write(const char* s, const char* tag) override;
	bool Write(const char* buf, int len, const char* tag) override;
	bool Write(const std::string& s, const char* tag) override;
	bool Write(const IPAddr& addr, const char* tag) override;
	bool Write(const IPPrefix& prefix, const char* tag) override;
	bool Write(const in_addr& addr, const char* tag) override;
	bool Write(const in6_addr& addr, const char* tag) override;
	bool WriteOpenTag(const char* tag) override;
	bool WriteCloseTag(const char* tag) override;
	bool WriteSeparator() override;
};

} // namespace zeek::detail
