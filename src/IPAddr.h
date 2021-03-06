// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <string>
#include <memory>

#include "zeek/threading/SerialTypes.h"

typedef in_addr in4_addr;

namespace zeek {

class String;
struct ConnID;

namespace detail {

class HashKey;

struct ConnIDKey {
	in6_addr ip1;
	in6_addr ip2;
	uint16_t port1;
	uint16_t port2;

	ConnIDKey() : port1(0), port2(0)
		{
		memset(&ip1, 0, sizeof(in6_addr));
		memset(&ip2, 0, sizeof(in6_addr));
		}

	ConnIDKey(const ConnIDKey& rhs)
		{
		*this = rhs;
		}

	bool operator<(const ConnIDKey& rhs) const { return memcmp(this, &rhs, sizeof(ConnIDKey)) < 0; }
	bool operator==(const ConnIDKey& rhs) const { return memcmp(this, &rhs, sizeof(ConnIDKey)) == 0; }

	ConnIDKey& operator=(const ConnIDKey& rhs)
		{
		if ( this != &rhs )
			memcpy(this, &rhs, sizeof(ConnIDKey));

		return *this;
		}
};

/**
 * Returns a map key for a given ConnID.
 */
ConnIDKey BuildConnIDKey(const ConnID& id);

} // namespace detail

/**
 * Class storing both IPv4 and IPv6 addresses.
 */
class IPAddr {
public:
	/**
	 * Address family.
	 */
	typedef IPFamily Family;

	/**
	 * Byte order.
	 */
	enum ByteOrder { Host, Network };

	/**
	 * Constructs the unspecified IPv6 address (all 128 bits zeroed).
	 */
	IPAddr()
		{
		memset(in6.s6_addr, 0, sizeof(in6.s6_addr));
		}

	/**
	 * Constructs an address instance from an IPv4 address.
	 *
	 * @param in6 The IPv6 address.
	 */
	explicit IPAddr(const in4_addr& in4)
		{
		memcpy(in6.s6_addr, v4_mapped_prefix, sizeof(v4_mapped_prefix));
		memcpy(&in6.s6_addr[12], &in4.s_addr, sizeof(in4.s_addr));
		}

	/**
	 * Constructs an address instance from an IPv6 address.
	 *
	 * @param in6 The IPv6 address.
	 */
	explicit IPAddr(const in6_addr& arg_in6) : in6(arg_in6) { }

	/**
	 * Constructs an address instance from a string representation.
	 *
	 * @param s String containing an IP address as either a dotted IPv4
	 * address or a hex IPv6 address.
	 */
	IPAddr(const std::string& s)
		{
		Init(s.data());
		}

	/**
	 * Constructs an address instance from a string representation.
	 *
	 * @param s ASCIIZ string containing an IP address as either a
	 * dotted IPv4 address or a hex IPv6 address.
	 */
	IPAddr(const char* s)
		{
		Init(s);
		}

	/**
	 * Constructs an address instance from a string representation.
	 *
	 * @param s String containing an IP address as either a dotted IPv4
	 * address or a hex IPv6 address.
	 */
	explicit IPAddr(const String& s);

	/**
	 * Constructs an address instance from a raw byte representation.
	 *
	 * @param family The address family.
	 *
	 * @param bytes A pointer to the raw byte representation. This must point
	 * to 4 bytes if \a family is IPv4, and to 16 bytes if \a family is
	 * IPv6.
	 *
	 * @param order Indicates whether the raw representation pointed to
	 * by \a bytes is stored in network or host order.
	 */
	IPAddr(Family family, const uint32_t* bytes, ByteOrder order);

	/**
	 * Copy constructor.
	 */
	IPAddr(const IPAddr& other) : in6(other.in6) { };

	/**
	 * Destructor.
	 */
	~IPAddr() = default;

	/**
	 * Returns the address' family.
	 */
	Family GetFamily() const
		{
		if ( memcmp(in6.s6_addr, v4_mapped_prefix, 12) == 0 )
			return IPv4;

		return IPv6;
		}

	/**
	 * Returns true if the address represents a loopback device.
	 */
	bool IsLoopback() const;

	/**
	 * Returns true if the address represents a multicast address.
	 */
	bool IsMulticast() const
		{
		if ( GetFamily() == IPv4 )
			return in6.s6_addr[12] == 224;

		return in6.s6_addr[0] == 0xff;
		}

	/**
	 * Returns true if the address represents a broadcast address.
	 */
	bool IsBroadcast() const
		{
		if ( GetFamily() == IPv4 )
			return ((in6.s6_addr[12] == 0xff) && (in6.s6_addr[13] == 0xff)
				&& (in6.s6_addr[14] == 0xff) && (in6.s6_addr[15] == 0xff));

		return false;
		}

	/**
	 * Retrieves the raw byte representation of the address.
	 *
	 * @param bytes The pointer to which \a bytes points will be set to
	 * the address of the raw representation in network-byte order.
	 * The return value indicates how many 32-bit words are valid starting at
	 * that address. The pointer will be valid as long as the address instance
	 * exists.
	 *
	 * @return The number of 32-bit words the raw representation uses. This
	 * will be 1 for an IPv4 address and 4 for an IPv6 address.
	 */
	int GetBytes(const uint32_t** bytes) const
		{
		if ( GetFamily() == IPv4 )
			{
			*bytes = (uint32_t*) &in6.s6_addr[12];
			return 1;
			}
		else
			{
			*bytes = (uint32_t*) in6.s6_addr;
			return 4;
			}
		}

	/**
	 * Retrieves a copy of the IPv6 raw byte representation of the address.
	 * If the internal address is IPv4, then the copied bytes use the
	 * IPv4 to IPv6 address mapping to return a full 16 bytes.
	 *
	 * @param bytes The pointer to a memory location in which the
	 * raw bytes of the address are to be copied.
	 *
	 * @param order The byte-order in which the returned raw bytes are copied.
	 * The default is network order.
	 */
	void CopyIPv6(uint32_t* bytes, ByteOrder order = Network) const
		{
		memcpy(bytes, in6.s6_addr, sizeof(in6.s6_addr));

		if ( order == Host )
			{
			for ( unsigned int i = 0; i < 4; ++i )
				bytes[i] = ntohl(bytes[i]);
			}
		}

	/**
	 * Retrieves a copy of the IPv6 raw byte representation of the address.
	 * @see CopyIPv6(uint32_t)
	 */
	void CopyIPv6(in6_addr* arg_in6) const
		{
		memcpy(arg_in6->s6_addr, in6.s6_addr, sizeof(in6.s6_addr));
		}

	/**
	 * Retrieves a copy of the IPv4 raw byte representation of the address.
	 * The caller should verify the address is of the IPv4 family type
	 * beforehand.  @see GetFamily().
	 *
	 * @param in4 The pointer to a memory location in which the raw bytes
	 * of the address are to be copied in network byte-order.
	 */
	void CopyIPv4(in4_addr* in4) const
		{
		memcpy(&in4->s_addr, &in6.s6_addr[12], sizeof(in4->s_addr));
		}

	/**
	 * Returns a key that can be used to lookup the IP Address in a hash table.
	 */
	std::unique_ptr<detail::HashKey> MakeHashKey() const;

	/**
	 * Masks out lower bits of the address.
	 *
	 * @param top_bits_to_keep The number of bits \a not to mask out,
	 * counting from the highest order bit. The value is always
	 * interpreted relative to the IPv6 bit width, even if the address
	 * is IPv4. That means if compute ``192.168.1.2/16``, you need to
	 * pass in 112 (i.e., 96 + 16). The value must be in the range from
	 * 0 to 128.
	 */
	void Mask(int top_bits_to_keep);

	/**
	 * Masks out top bits of the address.
	 *
	 * @param top_bits_to_chop The number of bits to mask out, counting
	 * from the highest order bit.  The value is always interpreted relative
	 * to the IPv6 bit width, even if the address is IPv4.  So to mask out
	 * the first 16 bits of an IPv4 address, pass in 112 (i.e., 96 + 16).
	 * The value must be in the range from 0 to 128.
	 */
	void ReverseMask(int top_bits_to_chop);

	/**
	 * Assignment operator.
	 */
	IPAddr& operator=(const IPAddr& other)
		{
		// No self-assignment check here because it's correct without it and
		// makes the common case faster.
		in6 = other.in6;
		return *this;
		}

	/**
	 * Bitwise OR operator returns the IP address resulting from the bitwise
	 * OR operation on the raw bytes of this address with another.
	 */
	IPAddr operator|(const IPAddr& other)
		{
		in6_addr result;
		for ( int i = 0; i < 16; ++i )
			result.s6_addr[i] = this->in6.s6_addr[i] | other.in6.s6_addr[i];

		return IPAddr(result);
		}

	/**
	 * Returns a string representation of the address. IPv4 addresses
	 * will be returned in dotted representation, IPv6 addresses in
	 * compressed hex.
	 */
	std::string AsString() const;

	/**
	 * Returns a string representation of the address suitable for inclusion
	 * in an URI.  For IPv4 addresses, this is the same as AsString(), but
	 * IPv6 addresses are encased in square brackets.
	 */
	std::string AsURIString() const
		{
		if ( GetFamily() == IPv4 )
			return AsString();

		return std::string("[") + AsString() + "]";
		}

	/**
	 * Returns a host-order, plain hex string representation of the address.
	 */
	std::string AsHexString() const;

	/**
	 * Returns a string representation of the address. This returns the
	 * same as AsString().
	 */
	operator std::string() const { return AsString(); }

	/**
	 * Returns a reverse pointer name associated with the IP address.
	 * For example, 192.168.0.1's reverse pointer is 1.0.168.192.in-addr.arpa.
	 */
	std::string PtrName() const;

	/**
	 * Comparison operator for IP address.
	 */
	friend bool operator==(const IPAddr& addr1, const IPAddr& addr2)
		{
		return memcmp(&addr1.in6, &addr2.in6, sizeof(in6_addr)) == 0;
		}

	friend bool operator!=(const IPAddr& addr1, const IPAddr& addr2)
		{
		return ! (addr1 == addr2);
		}

	/**
	 * Comparison operator IP addresses. This defines a well-defined order for
	 * IP addresses. However, the order does not necessarily correspond to
	 * their numerical values.
	 */
	friend bool operator<(const IPAddr& addr1, const IPAddr& addr2)
		{
		return memcmp(&addr1.in6, &addr2.in6, sizeof(in6_addr)) < 0;
		}

	friend bool operator<=(const IPAddr& addr1, const IPAddr& addr2)
		{
		return addr1 < addr2 || addr1 == addr2;
		}

	friend bool operator>=(const IPAddr& addr1, const IPAddr& addr2)
		{
		return ! ( addr1 < addr2 );
		}

	friend bool operator>(const IPAddr& addr1, const IPAddr& addr2)
		{
		return ! ( addr1 <= addr2 );
		}

	/** Converts the address into the type used internally by the
	  * inter-thread communication.
	  */
	void ConvertToThreadingValue(threading::Value::addr_t* v) const;

	friend detail::ConnIDKey detail::BuildConnIDKey(const ConnID& id);

	unsigned int MemoryAllocation() const { return padded_sizeof(*this); }

	/**
	 * Check if an IP prefix length would be valid against this IP address.
	 *
	 * @param length the IP prefix length to check
	 *
	 * @param len_is_v6_relative whether the length is relative to the full
	 * IPv6 address length (e.g. since IPv4 addrs are internally stored
	 * in v4-to-v6-mapped format, this parameter disambiguates whether
	 * a the length is in the usual 32-bit space for IPv4 or the full
	 * 128-bit space of IPv6 address.
	 *
	 * @return whether the prefix length is valid.
	 */
	bool CheckPrefixLength(uint8_t length, bool len_is_v6_relative = false) const;

	/**
	 * Converts an IPv4 or IPv6 string into a network address structure
	 * (IPv6 or v4-to-v6-mapping in network bytes order).
	 *
	 * @param s the IPv4 or IPv6 string to convert (ASCII, NUL-terminated).
	 *
	 * @param result buffer that the caller supplies to store the result.
	 *
	 * @return whether the conversion was successful.
	 */
	static bool ConvertString(const char* s, in6_addr* result);

	/**
	 * @param s the IPv4 or IPv6 string to convert (ASCII, NUL-terminated).
	 *
	 * @return whether the string is a valid IP address
	 */
	static bool IsValid(const char* s)
		{
		in6_addr tmp;
		return ConvertString(s, &tmp);
		}

	/**
	 * Unspecified IPv4 addr, "0.0.0.0".
	 */
	static const IPAddr v4_unspecified;

	/**
	 * Unspecified IPv6 addr, "::".
	 */
	static const IPAddr v6_unspecified;

private:
	friend class IPPrefix;

	/**
	 * Initializes an address instance from a string representation.
	 *
	 * @param s String containing an IP address as either a dotted IPv4
	 * address or a hex IPv6 address (ASCII, NUL-terminated).
	 */
	void Init(const char* s);

	in6_addr in6; // IPv6 or v4-to-v6-mapped address

	// Top 96 bits of a v4-mapped-addr.
	static constexpr uint8_t v4_mapped_prefix[12] = { 0, 0, 0, 0,
	                                                  0, 0, 0, 0,
	                                                  0, 0, 0xff, 0xff };
};

inline IPAddr::IPAddr(Family family, const uint32_t* bytes, ByteOrder order)
	{
	if ( family == IPv4 )
		{
		memcpy(in6.s6_addr, v4_mapped_prefix, sizeof(v4_mapped_prefix));
		memcpy(&in6.s6_addr[12], bytes, sizeof(uint32_t));

		if ( order == Host )
			{
			uint32_t* p = (uint32_t*) &in6.s6_addr[12];
			*p = htonl(*p);
			}
		}

	else
		{
		memcpy(in6.s6_addr, bytes, sizeof(in6.s6_addr));

		if ( order == Host )
			{
			for ( unsigned int i = 0; i < 4; ++ i)
				{
				uint32_t* p = (uint32_t*) &in6.s6_addr[i*4];
				*p = htonl(*p);
				}
			}
		}
	}

inline bool IPAddr::IsLoopback() const
	{
	if ( GetFamily() == IPv4 )
		return in6.s6_addr[12] == 127;

	else
		return ((in6.s6_addr[0] == 0) && (in6.s6_addr[1] == 0)
			&& (in6.s6_addr[2] == 0) && (in6.s6_addr[3] == 0)
			&& (in6.s6_addr[4] == 0) && (in6.s6_addr[5] == 0)
			&& (in6.s6_addr[6] == 0) && (in6.s6_addr[7] == 0)
			&& (in6.s6_addr[8] == 0) && (in6.s6_addr[9] == 0)
			&& (in6.s6_addr[10] == 0) && (in6.s6_addr[11] == 0)
			&& (in6.s6_addr[12] == 0) && (in6.s6_addr[13] == 0)
			&& (in6.s6_addr[14] == 0) && (in6.s6_addr[15] == 1));
	}

inline void IPAddr::ConvertToThreadingValue(threading::Value::addr_t* v) const
	{
	v->family = GetFamily();

	switch ( v->family ) {

	case IPv4:
		CopyIPv4(&v->in.in4);
		return;

	case IPv6:
		CopyIPv6(&v->in.in6);
		return;

	// Can't be reached.
	abort();
	}
	}

/**
 * Class storing both IPv4 and IPv6 prefixes
 * (i.e., \c 192.168.1.1/16 and \c FD00::/8.
 */
class IPPrefix
{
public:

	/**
	 * Constructs a prefix 0/0.
	 */
	IPPrefix() = default;

	/**
	 * Constructs a prefix instance from an IPv4 address and a prefix
	 * length.
	 *
	 * @param in4 The IPv4 address.
	 *
	 * @param length The prefix length in the range from 0 to 32.
	 */
	IPPrefix(const in4_addr& in4, uint8_t length);

	/**
	 * Constructs a prefix instance from an IPv6 address and a prefix
	 * length.
	 *
	 * @param in6 The IPv6 address.
	 *
	 * @param length The prefix length in the range from 0 to 128.
	 */
	IPPrefix(const in6_addr& in6, uint8_t length);

	/**
	 * Constructs a prefix instance from an IPAddr object and prefix length.
	 *
	 * @param addr The IP address.
	 *
	 * @param length The prefix length in the range from 0 to 128
	 *
	 * @param len_is_v6_relative Whether \a length is relative to the full
	 * 128 bits of an IPv6 address.  If false and \a addr is an IPv4
	 * address, then \a length is expected to range from 0 to 32.  If true
	 * \a length is expected to range from 0 to 128 even if \a addr is IPv4,
	 * meaning that the mask is to apply to the IPv4-mapped-IPv6 representation.
	 */
	IPPrefix(const IPAddr& addr, uint8_t length,
	         bool len_is_v6_relative = false);

	/**
	 * Copy constructor.
	 */
	IPPrefix(const IPPrefix& other)
		: prefix(other.prefix), length(other.length) { }

	/**
	 * Destructor.
	 */
	~IPPrefix() = default;

	/**
	 * Returns the prefix in the form of an IP address. The address will
	 * have all bits not part of the prefixed set to zero.
	 */
	const IPAddr& Prefix() const { return prefix; }

	/**
	 * Returns the bit length of the prefix, relative to the 32 bits
	 * of an IPv4 prefix or relative to the 128 bits of an IPv6 prefix.
	 */
	uint8_t Length() const
		{
		return prefix.GetFamily() == IPv4 ? length - 96 : length;
		}

	/**
	 * Returns the bit length of the prefix always relative to a full
	 * 128 bits of an IPv6 prefix (or IPv4 mapped to IPv6).
	 */
	uint8_t LengthIPv6() const { return length; }

	/** Returns true if the given address is part of the prefix.
	 *
	 * @param addr The address to test.
	 */
	bool Contains(const IPAddr& addr) const
		{
		IPAddr p(addr);
		p.Mask(length);
		return p  == prefix;
		}
	/**
	 * Assignment operator.
	 */
	IPPrefix& operator=(const IPPrefix& other)
		{
		// No self-assignment check here because it's correct without it and
		// makes the common case faster.
		prefix = other.prefix;
		length = other.length;
		return *this;
		}

	/**
	 * Returns a string representation of the prefix. IPv4 addresses
	 * will be returned in dotted representation, IPv6 addresses in
	 * compressed hex.
	 */
	std::string AsString() const;

	operator std::string() const	{ return AsString(); }

	/**
	 * Returns a key that can be used to lookup the IP Prefix in a hash table.
	 */
	std::unique_ptr<detail::HashKey> MakeHashKey() const;

	/** Converts the prefix into the type used internally by the
	  * inter-thread communication.
	  */
	void ConvertToThreadingValue(threading::Value::subnet_t* v) const
		{
		v->length = length;
		prefix.ConvertToThreadingValue(&v->prefix);
		}

	unsigned int MemoryAllocation() const { return padded_sizeof(*this); }

	/**
	 * Comparison operator for IP prefix.
	 */
	friend bool operator==(const IPPrefix& net1, const IPPrefix& net2)
		{
		return net1.Prefix() == net2.Prefix() && net1.Length() == net2.Length();
		}

	friend bool operator!=(const IPPrefix& net1, const IPPrefix& net2)
		{
		return ! (net1 == net2);
		}

	/**
	 * Comparison operator IP prefixes. This defines a well-defined order for
	 * IP prefix. However, the order does not necessarily corresponding to their
	 * numerical values.
	 */
	friend bool operator<(const IPPrefix& net1, const IPPrefix& net2)
		{
		if ( net1.Prefix() < net2.Prefix() )
			return true;

		else if ( net1.Prefix() == net2.Prefix() )
			return net1.Length() < net2.Length();

		else
			return false;
		}

	friend bool operator<=(const IPPrefix& net1, const IPPrefix& net2)
		{
		return net1 < net2 || net1 == net2;
		}

	friend bool operator>=(const IPPrefix& net1, const IPPrefix& net2)
		{
		return ! (net1 < net2 );
		}

	friend bool operator>(const IPPrefix& net1, const IPPrefix& net2)
		{
		return ! ( net1 <= net2 );
		}

	/**
	 * Converts an IPv4 or IPv6 prefix string into a network address prefix structure.
	 *
	 * @param s the IPv4 or IPv6 prefix string to convert (ASCII, NUL-terminated).
	 *
	 * @param result buffer that the caller supplies to store the result.
	 *
	 * @return whether the conversion was successful.
	 */
	static bool ConvertString(const char* s, IPPrefix* result);

	/**
	 * @param s the IPv4 or IPv6 prefix string to convert (ASCII, NUL-terminated).
	 *
	 * @return whether the string is a valid IP address prefix
	 */
	static bool IsValid(const char* s)
		{
		IPPrefix tmp;
		return ConvertString(s, &tmp);
		}

private:
	IPAddr prefix;	// We store it as an address with the non-prefix bits masked out via Mask().
	uint8_t length = 0;	// The bit length of the prefix relative to full IPv6 addr.
};

} // namespace zeek
