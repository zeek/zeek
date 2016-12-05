// See the file "COPYING" in the main distribution directory for copyright.

#ifndef IOSOURCE_PKTSRC_RX_RING_H
#define IOSOURCE_PKTSRC_RX_RING_H

extern "C" {
#include <linux/if_packet.h> // AF_PACKET, etc.
}
#include <stdint.h>
#include <stdexcept>

#define TPACKET_VERSION TPACKET_V3

class RX_RingException : public std::runtime_error {
public:
	RX_RingException(const std::string& what_arg) : std::runtime_error(what_arg) {}
};

class RX_Ring {
public:
	/**
	 * Constructor
	 */
	RX_Ring(int sock, size_t bufsize);
	~RX_Ring();

	bool GetNextPacket(tpacket3_hdr** hdr);
	void ReleasePacket();

protected:
	void InitLayout(size_t bufsize);
	void NextBlock();

private:
	struct tpacket_req3 layout;
	struct tpacket_block_desc** blocks;
	struct tpacket3_hdr* packet;

	unsigned int block_num;
	unsigned int packet_num;

	uint8_t* ring;
	size_t size;
};

#endif
