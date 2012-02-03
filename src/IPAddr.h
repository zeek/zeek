
#ifndef IPADDR_H
#define IPADDR_H

#include <netinet/in.h>
#include <string>

#include "BroString.h"
#include "util.h"

typedef in_addr in4_addr;

/// Class storing both IPv4 and IPv6 addresses.
class IPAddr
{
public:
	/// Address family.
	enum Family { IPv4, IPv6 };

	/// Byte order.
	enum ByteOrder { Host, Network };

	/// Constructs the unspecified IPv6 address (all 128 bits zeroed).
	IPAddr();

	/// Constructs an address instance from an IPv4 address.
	///
	/// @param in6 The IPv6 address.
	IPAddr(const in4_addr& in4);

	/// Constructs an address instance from an IPv6 address.
	///
	/// @param in6 The IPv6 address.
	IPAddr(const in6_addr& in6);

	/// Constructs an address instance from a string representation.
	///
	/// @param s String containing an IP address as either a dotted IPv4
	/// address or a hex IPv6 address.
	IPAddr(const std::string& s);

	/// Constructs an address instance from a string representation.
	///
	/// @param s String containing an IP address as either a dotted IPv4
	/// address or a hex IPv6 address.
	IPAddr(const BroString& s);

	/// Constructs an address instance from a raw byte representation.
	///
	/// @param family The address family.
	///
	/// @param bytes A pointer to the raw byte representation. This must point
	/// to 4 bytes if \a family is IPv4, and to 16 bytes if \a family is
	/// IPv6.
	///
	/// @param order Indicates whether the raw representation pointed to
	/// by \a bytes is stored in network or host order.
	IPAddr(Family family, const uint32_t* bytes, ByteOrder order);

	/// Copy constructor.
	IPAddr(const IPAddr& other);

	/// Destructor.
	~IPAddr();

	/// Returns the address' family.
	Family family() const;

	/// Returns true if the address represents a loopback device.
	bool IsLoopback() const;

	/// Returns true if the address represents a multicast address.
	bool IsMulticast() const;

	/// Returns true if the address represents a broadcast address.
	bool IsBroadcast() const;

	/// Retrieves the raw byte representation of the address.
	///
	/// @param bytes The pointer to which \a bytes points will be set to
	/// the address of the raw representation in network-byte order.
	/// The return value indicates how many 32-bit words are valid starting at
	/// that address. The pointer will be valid as long as the address instance
	/// exists.
	///
	/// @return The number of 32-bit words the raw representation uses. This
	/// will be 1 for an IPv4 address and 4 for an IPv6 address.
	int GetBytes(uint32_t** bytes);
	int GetBytes(const uint32_t** bytes) const;

	/// Retrieves a copy of the IPv6 raw byte representation of the address.
	/// If the internal address is IPv4, then the copied bytes use the
	/// IPv4 to IPv6 address mapping to return a full 16 bytes.
	///
	/// @param bytes The pointer to a memory location in which the
	/// raw bytes of the address are to be copied in network byte-order.
	void CopyIPv6(uint32_t* bytes) const;

	/// Masks out lower bits of the address.
	///
	/// @param top_bits_to_keep The number of bits \a not to mask out,
	/// counting from the highest order bit. The value is always
	/// interpreted relative to the IPv6 bit width, even if the address
	/// is IPv4. That means if compute ``192.168.1.2/16``, you need to
	/// pass in 112 (i.e., 96 + 16). The value must be in the range from
	/// 0 to 128.
	void Mask(int top_bits_to_keep);

	/// Masks out top bits of the address.
	///
	/// @param top_bits_to_chop The number of bits to mask out, counting
	/// from the highest order bit.  The value is always interpreted relative
	/// to the IPv6 bit width, even if the address is IPv4.  So to mask out
	/// the first 16 bits of an IPv4 address, pass in 112 (i.e., 96 + 16).
	/// The value must be in the range from 0 to 128.
	void ReverseMask(int top_bits_to_chop);

	/// Assignment operator.
	IPAddr& operator=(const IPAddr& other);

	/// Returns a string representation of the address. IPv4 addresses
	/// will be returned in dotted representation, IPv6 addresses in
	/// compressed hex.
	operator std::string() const;

	/// Comparison operator for IP address.
	friend bool operator==(const IPAddr& addr1, const IPAddr& addr2);
	friend bool operator!=(const IPAddr& addr1, const IPAddr& addr2);

	/// Comparison operator IP addresses. This defines a well-defined order for
	/// IP addresses. However, the order does not necessarily correspond to
	/// their numerical values.
	friend bool operator<(const IPAddr& addr1, const IPAddr& addr2);

	unsigned int MemoryAllocation() const { return padded_sizeof(*this); }

private:
	in6_addr in6; // IPv6 or v4-to-v6-mapped address
	static const uint8_t v4_mapped_prefix[12]; // top 96 bits of v4-mapped-addr

	/// Initializes an address instance from a string representation.
	///
	/// @param s String containing an IP address as either a dotted IPv4
	/// address or a hex IPv6 address.
	void Init(const std::string& s);
};

/// Class storing both IPv4 and IPv6 prefixes
/// (i.e., \c 192.168.1.1/16 and \c FD00::/8.
class IPPrefix
{
public:
	/// Constructs a prefix instance from an IPv4 address and a prefix
	/// length.
	///
	/// @param in4 The IPv4 address.
	///
	/// @param length The prefix length in the range from 0 to 32.
	IPPrefix(const in4_addr& in4, uint8_t length);

	/// Constructs a prefix instance from an IPv6 address and a prefix
	/// length.
	///
	/// @param in6 The IPv6 address.
	///
	/// @param length The prefix length in the range from 0 to 128.
	IPPrefix(const in6_addr& in6, uint8_t length);

	/// Constructs a prefix instance from an IPAddr object and prefix length.
	///
	/// @param addr The IP address.
	///
	/// @param length The prefix length in the range from 0 to 128
	IPPrefix(const IPAddr& addr, uint8_t length);

	/// Constructs a prefix instance from IP string representation and length.
	///
	/// @param s String containing an IP address as either a dotted IPv4
	/// address or a hex IPv6 address.
	///
	/// @param length The prefix length in the range from 0 to 128
	IPPrefix(const std::string& s, uint8_t length);

	/// Copy constructor.
	IPPrefix(const IPPrefix& other);

	/// Destructor.
	~IPPrefix();

	/// Returns the prefix in the form of an IP address. The address will
	/// have all bits not part of the prefixed set to zero.
	const IPAddr& Prefix() const;

	/// Returns the bit length of the prefix, relative to the 32 bits
	/// of an IPv4 prefix or relative to the 128 bits of an IPv6 prefix.
	uint8_t Length() const;

	/// Returns the bit length of the prefix always relative to a full
	/// 128 bits of an IPv6 prefix (or IPv4 mapped to IPv6).
	uint8_t LengthIPv6() const;

	/// Assignment operator.
	IPPrefix& operator=(const IPPrefix& other);

	/// Returns a string representation of the prefix. IPv4 addresses
	/// will be returned in dotted representation, IPv6 addresses in
	/// compressed hex.
	operator std::string() const;

	unsigned int MemoryAllocation() const { return padded_sizeof(*this); }

private:
	IPAddr prefix;	// We store it as an address with the non-prefix bits masked out via Mask().
	uint8_t length;	// The bit length of the prefix relative to full IPv6 addr.
};

/// Comparison operator for IP prefix.
extern bool operator==(const IPPrefix& net1, const IPPrefix& net2);

/// Comparison operator IP prefixes. This defines a well-defined order for
/// IP prefix. However, the order does not necessarily corresponding to their
/// numerical values.
extern bool operator<(const IPPrefix& net1, const IPPrefix& net2);

#endif
