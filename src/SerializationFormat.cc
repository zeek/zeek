#include "zeek/SerializationFormat.h"

#include <cctype>

#include "zeek/DebugLogger.h"
#include "zeek/IPAddr.h"
#include "zeek/Reporter.h"
#include "zeek/net_util.h"

namespace zeek::detail
	{

const float SerializationFormat::GROWTH_FACTOR = 2.5;

SerializationFormat::SerializationFormat()
	: output(), output_size(), output_pos(), input(), input_len(), input_pos(), bytes_written(),
	  bytes_read()
	{
	}

SerializationFormat::~SerializationFormat()
	{
	free(output);
	}

void SerializationFormat::StartRead(const char* data, uint32_t arg_len)
	{
	input = data;
	input_len = arg_len;
	input_pos = 0;
	bytes_read = 0;
	}

void SerializationFormat::EndRead()
	{
	input = nullptr;
	}

void SerializationFormat::StartWrite()
	{
	if ( output && output_size > INITIAL_SIZE )
		{
		free(output);
		output = nullptr;
		}

	if ( ! output )
		{
		output = (char*)util::safe_malloc(INITIAL_SIZE);
		output_size = INITIAL_SIZE;
		}

	output_pos = 0;
	bytes_written = 0;
	}

uint32_t SerializationFormat::EndWrite(char** data)
	{
	uint32_t rval = output_pos;
	*data = output;
	output = nullptr;
	output_size = 0;
	output_pos = 0;
	return rval;
	}

bool SerializationFormat::ReadData(void* b, size_t count)
	{
	if ( input_pos + count > input_len )
		{
		reporter->Error("data underflow during read in binary format");
		abort();
		return false;
		}

	memcpy(b, input + input_pos, count);
	input_pos += count;
	bytes_read += count;

	return true;
	}

bool SerializationFormat::WriteData(const void* b, size_t count)
	{
	// Increase buffer if necessary.
	bool size_changed = false;
	while ( output_pos + count > output_size )
		{
		output_size *= GROWTH_FACTOR;
		size_changed = true;
		}

	// The glibc standard states explicitly that calling realloc with the same
	// size is a no-op, but the same claim can't be made on other platforms.
	// There's really no reason to do that though.
	if ( size_changed )
		output = (char*)util::safe_realloc(output, output_size);

	memcpy(output + output_pos, b, count);
	output_pos += count;
	bytes_written += count;

	return true;
	}

BinarySerializationFormat::BinarySerializationFormat() { }

BinarySerializationFormat::~BinarySerializationFormat() { }

bool BinarySerializationFormat::Read(int* v, const char* tag)
	{
	uint32_t tmp;
	if ( ! ReadData(&tmp, sizeof(tmp)) )
		return false;

	*v = (int)ntohl(tmp);
	DBG_LOG(DBG_SERIAL, "Read int %d [%s]", *v, tag);
	return true;
	}

bool BinarySerializationFormat::Read(uint16_t* v, const char* tag)
	{
	if ( ! ReadData(v, sizeof(*v)) )
		return false;

	*v = ntohs(*v);
	DBG_LOG(DBG_SERIAL, "Read uint16_t %hu [%s]", *v, tag);
	return true;
	}

bool BinarySerializationFormat::Read(uint32_t* v, const char* tag)
	{
	if ( ! ReadData(v, sizeof(*v)) )
		return false;

	*v = ntohl(*v);
	DBG_LOG(DBG_SERIAL, "Read uint32_t %" PRIu32 " [%s]", *v, tag);
	return true;
	}

bool BinarySerializationFormat::Read(int64_t* v, const char* tag)
	{
	uint32_t x[2];
	if ( ! ReadData(x, sizeof(x)) )
		return false;

	*v = ((int64_t(ntohl(x[0]))) << 32) | ntohl(x[1]);
	DBG_LOG(DBG_SERIAL, "Read int64_t %" PRId64 " [%s]", *v, tag);
	return true;
	}

bool BinarySerializationFormat::Read(uint64_t* v, const char* tag)
	{
	uint32_t x[2];
	if ( ! ReadData(x, sizeof(x)) )
		return false;

	*v = ((uint64_t(ntohl(x[0]))) << 32) | ntohl(x[1]);
	DBG_LOG(DBG_SERIAL, "Read uint64_t %" PRIu64 " [%s]", *v, tag);
	return true;
	}

bool BinarySerializationFormat::Read(bool* v, const char* tag)
	{
	char c;
	if ( ! ReadData(&c, 1) )
		return false;

	*v = c == '\1' ? true : false;
	DBG_LOG(DBG_SERIAL, "Read bool %s [%s]", *v ? "true" : "false", tag);
	return true;
	}

bool BinarySerializationFormat::Read(double* d, const char* tag)
	{
	if ( ! ReadData(d, sizeof(*d)) )
		return false;

	*d = ntohd(*d);
	DBG_LOG(DBG_SERIAL, "Read double %.6f [%s]", *d, tag);
	return true;
	}

bool BinarySerializationFormat::Read(char* v, const char* tag)
	{
	bool ret = ReadData(v, 1);
	DBG_LOG(DBG_SERIAL, "Read char %s [%s]", util::fmt_bytes(v, 1), tag);
	return ret;
	}

bool BinarySerializationFormat::Read(char** str, int* len, const char* tag)
	{
	int l;
	if ( ! ReadData(&l, sizeof(l)) )
		return false;

	l = ntohl(l);
	char* s = new char[l + 1];

	if ( ! ReadData(s, l) )
		{
		delete[] s;
		*str = nullptr;
		return false;
		}

	if ( len )
		*len = l;
	else
		{
		// If len isn't given, make sure that the string
		// doesn't contain any nulls.
		for ( int i = 0; i < l; i++ )
			if ( ! s[i] )
				{
				reporter->Error("binary Format: string contains null; replaced by '_'");
				s[i] = '_';
				}
		}

	s[l] = '\0';

	*str = s;

	DBG_LOG(DBG_SERIAL, "Read %d bytes |%s| [%s]", l, util::fmt_bytes(*str, l), tag);
	return true;
	}

bool BinarySerializationFormat::Read(std::string* v, const char* tag)
	{
	char* buffer;
	int len;

	if ( ! Read(&buffer, &len, tag) )
		return false;

	*v = std::string(buffer, len);

	delete[] buffer;
	return true;
	}

bool BinarySerializationFormat::Read(IPAddr* addr, const char* tag)
	{
	int n = 0;
	if ( ! Read(&n, "addr-len") )
		return false;

	if ( n != 1 && n != 4 )
		return false;

	uint32_t raw[4];

	for ( int i = 0; i < n; ++i )
		{
		if ( ! Read(&raw[i], "addr-part") )
			return false;

		raw[i] = htonl(raw[i]);
		}

	if ( n == 1 )
		*addr = IPAddr(IPv4, raw, IPAddr::Network);
	else
		*addr = IPAddr(IPv6, raw, IPAddr::Network);

	return true;
	}

bool BinarySerializationFormat::Read(IPPrefix* prefix, const char* tag)
	{
	IPAddr addr;
	int len;

	if ( ! (Read(&addr, "prefix") && Read(&len, "width")) )
		return false;

	*prefix = IPPrefix(addr, len);
	return true;
	}

bool BinarySerializationFormat::Read(struct in_addr* addr, const char* tag)
	{
	uint32_t* bytes = (uint32_t*)&addr->s_addr;

	if ( ! Read(&bytes[0], "addr4") )
		return false;

	bytes[0] = htonl(bytes[0]);
	return true;
	}

bool BinarySerializationFormat::Read(struct in6_addr* addr, const char* tag)
	{
	uint32_t* bytes = (uint32_t*)&addr->s6_addr;

	for ( int i = 0; i < 4; ++i )
		{
		if ( ! Read(&bytes[i], "addr6-part") )
			return false;

		bytes[i] = htonl(bytes[i]);
		}

	return true;
	}

bool BinarySerializationFormat::Write(char v, const char* tag)
	{
	DBG_LOG(DBG_SERIAL, "Write char %s [%s]", util::fmt_bytes(&v, 1), tag);
	return WriteData(&v, 1);
	}

bool BinarySerializationFormat::Write(uint16_t v, const char* tag)
	{
	DBG_LOG(DBG_SERIAL, "Write uint16_t %hu [%s]", v, tag);
	v = htons(v);
	return WriteData(&v, sizeof(v));
	}

bool BinarySerializationFormat::Write(uint32_t v, const char* tag)
	{
	DBG_LOG(DBG_SERIAL, "Write uint32_t %" PRIu32 " [%s]", v, tag);
	v = htonl(v);
	return WriteData(&v, sizeof(v));
	}

bool BinarySerializationFormat::Write(int v, const char* tag)
	{
	DBG_LOG(DBG_SERIAL, "Write int %d [%s]", v, tag);
	uint32_t tmp = htonl((uint32_t)v);
	return WriteData(&tmp, sizeof(tmp));
	}

bool BinarySerializationFormat::Write(uint64_t v, const char* tag)
	{
	DBG_LOG(DBG_SERIAL, "Write uint64_t %" PRIu64 " [%s]", v, tag);
	uint32_t x[2];
	x[0] = htonl(v >> 32);
	x[1] = htonl(v & 0xffffffff);
	return WriteData(x, sizeof(x));
	}

bool BinarySerializationFormat::Write(int64_t v, const char* tag)
	{
	DBG_LOG(DBG_SERIAL, "Write int64_t %" PRId64 " [%s]", v, tag);
	uint32_t x[2];
	x[0] = htonl(v >> 32);
	x[1] = htonl(v & 0xffffffff);
	return WriteData(x, sizeof(x));
	}

bool BinarySerializationFormat::Write(double d, const char* tag)
	{
	DBG_LOG(DBG_SERIAL, "Write double %.6f [%s]", d, tag);
	d = htond(d);
	return WriteData(&d, sizeof(d));
	}

bool BinarySerializationFormat::Write(bool v, const char* tag)
	{
	DBG_LOG(DBG_SERIAL, "Write bool %s [%s]", v ? "true" : "false", tag);
	char c = v ? '\1' : '\0';
	return WriteData(&c, 1);
	}

bool BinarySerializationFormat::Write(const char* s, const char* tag)
	{
	return Write(s, strlen(s), tag);
	}

bool BinarySerializationFormat::Write(const std::string& s, const char* tag)
	{
	return Write(s.data(), s.size(), tag);
	}

bool BinarySerializationFormat::Write(const IPAddr& addr, const char* tag)
	{
	const uint32_t* raw;
	int n = addr.GetBytes(&raw);

	assert(n == 1 || n == 4);

	if ( ! Write(n, "addr-len") )
		return false;

	for ( int i = 0; i < n; ++i )
		{
		if ( ! Write(static_cast<uint32_t>(ntohl(raw[i])), "addr-part") )
			return false;
		}

	return true;
	}

bool BinarySerializationFormat::Write(const IPPrefix& prefix, const char* tag)
	{
	return Write(prefix.Prefix(), "prefix") && Write(prefix.Length(), "width");
	}

bool BinarySerializationFormat::Write(const struct in_addr& addr, const char* tag)
	{
	const uint32_t* bytes = (uint32_t*)&addr.s_addr;

	if ( ! Write(static_cast<uint32_t>(ntohl(bytes[0])), "addr4") )
		return false;

	return true;
	}

bool BinarySerializationFormat::Write(const struct in6_addr& addr, const char* tag)
	{
	const uint32_t* bytes = (uint32_t*)&addr.s6_addr;

	for ( int i = 0; i < 4; ++i )
		{
		if ( ! Write(static_cast<uint32_t>(ntohl(bytes[i])), "addr6-part") )
			return false;
		}

	return true;
	}

bool BinarySerializationFormat::WriteOpenTag(const char* tag)
	{
	return true;
	}

bool BinarySerializationFormat::WriteCloseTag(const char* tag)
	{
	return true;
	}

bool BinarySerializationFormat::WriteSeparator()
	{
	return true;
	}

bool BinarySerializationFormat::Write(const char* buf, int len, const char* tag)
	{
	DBG_LOG(DBG_SERIAL, "Write bytes |%s| [%s]", util::fmt_bytes(buf, len), tag);
	uint32_t l = htonl(len);
	return WriteData(&l, sizeof(l)) && WriteData(buf, len);
	}

	} // namespace zeek::detail
