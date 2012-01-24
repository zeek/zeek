
#ifndef IPADDR_H
#define IPADDR_H

/// Class storing both IPv4 and IPv6 addresses.
class IPAddr
{
public:
	/// Address family.
	enum Family { IPv4, IPv6 };

	/// Byte order.
	enum ByteOrder { Host, Network };

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
	IPAddr(const string& s);

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
	/// be \a bytes is stored in network or host order.
	IPAddr(Family family, const u_char* bytes, ByteOrder order);

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

	/// Returs true if the address represents a broadcast address.
	bool IsBroadcast() const;

	/// Retrieves the raw byte representation of the address.
	///
	/// @param bytes The pointer to which \a bytes points will be set to
	/// the address of the raw representation. The return value indicates
	/// how many bytes are valid starting at that address. The pointer
	/// will be valid as long as the address instance exists.
	///
	/// @return The number of bytes the raw representation uses. This
	/// will be 4 for an IPv4 address and 32 for an IPv6 address. 
	int GetBytes(unsigned u_char** bytes); // Returns network-byte order.

	/// Masks out lower bits of the address.
	///
	/// @param top_bits_to_keep The number of bits \a not to mask out,
	/// counting from the highest order bit. The value is always
	/// interpreted relative to the IPv6 bit width, even if the address
	/// is IPv4. That means if compute ``192.168.1.2/16``, you need to
	/// pass in 112 (i.e., 96 + 16). The value must be in the range from
	/// 0 to 128.
	void Mask(int top_bits_to_keep);

	/// Assignment operator.
	const IPAddr& operator=(const IPAddr& other);

	/// Returns a string representation of the address. IPv4 addresses
	/// will be returned in dotted representation, IPv6 addresses in
	/// compressed hex.
	operator string() const;

private:
	struct in6_addr in6; // This stored IPv6 addresses via the standard v4-to-v6 mapping.
};

/// Comparision operator for IP addresss.
extern bool operator==(const IPAddr& addr1, const IPAddr& addr2) const;

/// Comparision operator IP addresses. This defines a well-defined order for
/// IP addresses. However, the order does not necessarily correspond to their
/// numerical values.
extern bool operator<(const IPAddr& addr1, const IPAddr& addr2) const;

/// Class storing both IPv4 and IPv6 prefixes (i.e., \c 192.168.1.1/16 and \c FD00::/8.
class IPPrefix
{
public:
	/// Constructs a prefix instance from an IPv4 address and a prefix
	/// length.
	///
	/// @param addr The IPv4 address.
	///
	/// @param length The prefix length in the range from 0 to 32.
	IPPrefix(const in4_addr& in4, uint16_t length);

	/// Constructs a prefix instance from an IPv6 address and a prefix
	/// length.
	///
	/// @param addr The IPv6 address.
	///
	/// @param length The prefix length in the range from 0 to 128.
	IPPrefix(const in6_addr& in6, uint16_t length);

	/// Copy constructor.
	IPPrefix(const IPPrefix& other);

	/// Destructor.
	~IPPrefix();

	/// Returns the prefix in the form of an IP address. The address will
	/// have all bits not part of the prefixed set to zero.
	const IPAddr& Prefix() const;

	/// Returns the bit length of the prefix.
	uint16_t Length() const;

	/// Assignment operator.
	const IPPrefix& operator=(const IPPrefix& other);

	/// Returns a string representation of the prefix. IPv4 addresses
	/// will be returned in dotted representation, IPv6 addresses in
	/// compressed hex.
	operator string() const;

private:
	IPAddr prefix;	// We store it as an address with the non-prefix bits masked out via Mask().
	uint16_t mask;	// The bit length.        
};

/// Comparision operator for IP prefix.
extern bool operator==(const IPPrefix& net1, const IPPrefix& net2) const;

/// Comparision operator IP prefixes. This defines a well-defined order for
/// IP prefix. However, the order does not necessarily corresponding to their
/// numerical values.
extern bool operator<(const IPPrefix& net1, const IPPrefix& net2) const;

#endif
