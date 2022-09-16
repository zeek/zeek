
#include "RX_Ring.h"

#include <cstring>
#include <utility>

extern "C" {
#include <linux/if_packet.h>  // AF_PACKET, etc.
#include <sys/socket.h>       // socketopt consts
#include <sys/mman.h>         // mmap
#include <unistd.h>           // sysconf
}

RX_Ring::RX_Ring(int sock, size_t bufsize, size_t blocksize, int blocktimeout_msec)
	{
	int ret, ver = TPACKET_VERSION;

	if ( sock < 0 )
		throw RX_RingException("invalid socket");

	// Configure socket
	ret = setsockopt(sock, SOL_PACKET, PACKET_VERSION, &ver, sizeof(ver));
	if ( ret )
		throw RX_RingException("unable to set TPacket version");

	InitLayout(bufsize, blocksize, blocktimeout_msec);
	ret = setsockopt(sock, SOL_PACKET, PACKET_RX_RING, (uint8_t *) &layout,
		sizeof(layout));
	if ( ret )
		throw RX_RingException("unable to set ring layout");

	// Map memory
	size = layout.tp_block_size * layout.tp_block_nr;
	ring = (uint8_t *) mmap(NULL, size, PROT_READ | PROT_WRITE,
		MAP_SHARED, sock, 0);
	if ( ring == MAP_FAILED )
		throw RX_RingException("unable to map ring memory");

	block_num = packet_num = 0;
	packet = NULL;

	// Init block mapping
	blocks = new tpacket_block_desc*[layout.tp_block_nr];
	for ( unsigned int i = 0; i < layout.tp_block_nr; i++ )
		blocks[i] = (struct tpacket_block_desc *)(ring +
			i * layout.tp_block_size);
	}

RX_Ring::~RX_Ring()
	{
	ReleasePacket();

	delete[] blocks;
	munmap(ring, size);

	blocks = 0;
	size = 0;
	}

bool RX_Ring::GetNextPacket(tpacket3_hdr** hdr)
	{
	struct tpacket_hdr_v1 *block_hdr = &(blocks[block_num]->hdr.bh1);

	if ( (block_hdr->block_status & TP_STATUS_USER) == 0 )
		return false;

	if ( packet == NULL )
		{
		// New block
		packet_num = block_hdr->num_pkts;
		if ( packet_num == 0 )
			{
			NextBlock();
			return false;
			}
		packet = (struct tpacket3_hdr *)
			((uint8_t *) blocks[block_num] + block_hdr->offset_to_first_pkt);
		}
	else
		// Continue with block
		packet = (struct tpacket3_hdr *)
			((uint8_t *) packet + packet->tp_next_offset);

	*hdr = packet;
	packet_num--;
	return true;
	}

void RX_Ring::ReleasePacket()
	{
	if ( packet_num == 0 )
		NextBlock();
	}

void RX_Ring::InitLayout(size_t bufsize, size_t blocksize, int blocktimeout_msec)
	{
	memset(&layout, 0, sizeof(layout));
	layout.tp_block_size = blocksize;
	layout.tp_frame_size = TPACKET_ALIGNMENT << 7; // Seems to be irrelevant for V3
	layout.tp_block_nr = bufsize / layout.tp_block_size;
	layout.tp_frame_nr = (layout.tp_block_size / layout.tp_frame_size) * layout.tp_block_nr;
	layout.tp_retire_blk_tov = blocktimeout_msec;
	}

void RX_Ring::NextBlock()
	{
	struct tpacket_hdr_v1 *block_hdr = &(blocks[block_num]->hdr.bh1);

	block_hdr->block_status = TP_STATUS_KERNEL;
	block_num = (block_num +1) % layout.tp_block_nr;
	packet = NULL;
	}
