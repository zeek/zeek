// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <sys/types.h> // for u_char
#include <vector>

#include "zeek/iosource/BPF_Program.h"
#include "zeek/iosource/IOSource.h"
#include "zeek/iosource/Packet.h"

struct pcap_pkthdr;

namespace zeek::iosource
	{

/**
 * Base class for packet sources.
 */
class PktSrc : public IOSource
	{
public:
	static const uint32_t NETMASK_UNKNOWN = 0xffffffff;

	/**
	 * Struct for returning statistics on a packet source.
	 */
	struct Stats
		{
		/**
		 * Packets received by source after filtering (w/o drops).
		 */
		uint64_t received;

		/**
		 * Packets dropped by source.
		 */
		uint64_t dropped; // pkts dropped

		/**
		 * Total number of packets on link before filtering.
		 * Optional, can be left unset if not available.
		 */
		uint64_t link;

		/**
		 * Bytes received by source after filtering (w/o drops).
		 */
		uint64_t bytes_received;

		Stats() { received = dropped = link = bytes_received = 0; }
		};

	/**
	 * Constructor.
	 */
	PktSrc();

	/**
	 * Destructor.
	 */
	~PktSrc() override;

	/**
	 * Returns the path associated with the source. This is the interface
	 * name for live source, and a filename for offline sources.
	 */
	const std::string& Path() const;

	/**
	 * Returns true if this is a live source.
	 */
	bool IsLive() const;

	/**
	 * Returns the link type of the source.
	 */
	int LinkType() const;

	/**
	 * Returns the netmask associated with the source, or \c
	 * NETMASK_UNKNOWN if unknown.
	 */
	uint32_t Netmask() const;

	/**
	 * Returns true if the source has flagged an error.
	 */
	bool IsError() const;

	/**
	 * If the source encountered an error, returns a corresponding error
	 * message. Returns an empty string otherwise.
	 */
	const char* ErrorMsg() const;

	/**
	 * Precompiles a BPF filter and associates the given index with it.
	 * The compiled filter will be then available via \a GetBPFFilter().
	 *
	 * This is primarily a helper for packet source implementations that
	 * want to apply BPF filtering to their packets.
	 *
	 * @param index The index to associate with the filter.
	 *
	 * @param BPF filter The filter string to precompile.
	 *
	 * @return True on success, false if a problem occurred.
	 */
	virtual bool PrecompileBPFFilter(int index, const std::string& filter);

	/**
	 * Returns the precompiled BPF filter associated with a given index,
	 * if any, as compiled by \a PrecompileBPFFilter().
	 *
	 * This is primarily a helper for packet source implementation that
	 * want to apply BPF filtering to their packets.
	 *
	 * @return The BPF filter associated, or null if none has been
	 * (successfully) compiled.
	 */
	detail::BPF_Program* GetBPFFilter(int index);

	/**
	 * Applies a precompiled BPF filter to a packet. This will close the
	 * source with an error message if no filter with that index has been
	 * compiled.
	 *
	 * This is primarily a helper for packet source implementation that
	 * want to apply BPF filtering to their packets.
	 *
	 * @param index The index of the filter to apply.
	 *
	 * @param hdr The header of the packet to filter.
	 *
	 * @param pkt The content of the packet to filter.
	 *
	 * @return True if it matches.
	 */
	bool ApplyBPFFilter(int index, const struct pcap_pkthdr* hdr, const u_char* pkt);

	/**
	 * Returns the packet currently being processed, if available.
	 *
	 * @param pkt A pointer to pass the content of the current packet
	 * back.
	 *
	 * @return True if the current packet is available, or false if not.
	 */
	bool GetCurrentPacket(const Packet** hdr);

	// PacketSource interace for derived classes to override.

	/**
	 * Precompiles a filter and associates a given index with it. The
	 * filter syntax is defined by the packet source's implenentation.
	 *
	 * Derived classes can override this method to implement their own
	 * filtering. If not overriden, it uses the pcap-based BPF filtering
	 * by default.
	 *
	 * @param index The index to associate with the filter
	 *
	 * @param filter The filter string to precompile.
	 *
	 * @return True on success, false if a problem occurred or filtering
	 * is not supported.
	 */
	virtual bool PrecompileFilter(int index, const std::string& filter)
		{
		return PrecompileBPFFilter(index, filter);
		}

	/**
	 * Activates a precompiled filter with the given index.
	 *
	 * Derived classes must implement this to implement their filtering.
	 * If they want to use BPF but don't support it natively, they can
	 * call the corresponding helper method provided by \a PktSrc.
	 *
	 * @param index The index of the filter to activate.
	 *
	 * @return True on success, false if a problem occurred or the
	 * filtering is not supported.
	 */
	virtual bool SetFilter(int index) = 0;

	/**
	 * Returns current statistics about the source.
	 *
	 * Derived classes must implement this method.
	 *
	 * @param stats A statistics structure that the method fill out.
	 */
	virtual void Statistics(Stats* stats) = 0;

	/**
	 * Return the next timeout value for this source. This should be
	 * overridden by source classes where they have a timeout value
	 * that can wake up the poll.
	 *
	 * @return A value for the next time that the source thinks the
	 * poll should time out in seconds from the current time. Return
	 * -1 if this should should not be considered.
	 */
	virtual double GetNextTimeout() override;

protected:
	friend class Manager;
	friend class ManagerBase;

	// Methods to use by derived classes.

	/**
	 * Structure to pass back information about the packet source to the
	 * base class. Derived class pass an instance of this to \a Opened().
	 */
	struct Properties
		{
		/**
		 * The path associated with the source. This is the interface
		 * name for live source, and a filename for offline sources.
		 */
		std::string path;

		/**
		 * A file descriptor suitable to use with \a select() for
		 * determining if there's input available from this source.
		 */
		int selectable_fd;

		/**
		 * The link type for packets from this source.
		 */
		int link_type;

		/**
		 * Returns the netmask associated with the source, or \c
		 * NETMASK_UNKNOWN if unknown.
		 */
		uint32_t netmask;

		/**
		 * True if the source is reading live inout, false for
		 * working offline.
		 */
		bool is_live;

		Properties();
		};

	/**
	 * Called from the implementations of \a Open() to signal that the
	 * source has been successully opened.
	 *
	 * @param props A properties instance describing the now open source.
	 */
	void Opened(const Properties& props);

	/**
	 * Called from the implementations of \a Close() to signal that the
	 * source has been closed.
	 */
	void Closed();

	/**
	 * Can be called from derived classes to send an informational
	 * message to the user.
	 *
	 * @param msg The message to pass on.
	 */
	void Info(const std::string& msg);

	/**
	 * Can be called from derived classes to flag send an error.
	 *
	 * @param msg The message going with the error.
	 */
	void Error(const std::string& msg);

	/**
	 * Can be called from derived classes to flag a "weird" situation.
	 *
	 * @param msg The message to pass on.
	 *
	 * @param pkt The packet associated with the weird, or null if none.
	 */
	void Weird(const std::string& msg, const Packet* pkt);

	/**
	 * Can be called from derived classes to flag an internal error,
	 * which will abort execution.
	 *
	 * @param msg The message to pass on.
	 */
	void InternalError(const std::string& msg);

	// PktSrc interface for derived classes to implement.

	/**
	 * Called by the manager system to open the source.
	 *
	 * Derived classes must implement this method. If successful, the
	 * implementation must call \a Opened(); if not, it must call Error()
	 * with a corresponding message.
	 */
	virtual void Open() = 0;

	/**
	 * Called by the manager system to close the source.
	 *
	 * Derived classes must implement this method. If successful, the
	 * implementation must call \a Closed(); if not, it must call Error()
	 * with a corresponding message.
	 */
	virtual void Close() = 0;

	/**
	 * Provides the next packet from the source.
	 *
	 * @param pkt The packet structure to fill in with the packet's
	 * information. The callee keep ownership of the data but must
	 * guarantee that it stays available at least until \a
	 * DoneWithPacket() is called.  It is guaranteed that no two calls to
	 * this method will hapen with \a DoneWithPacket() in between.
	 *
	 * @return True if a packet is available and *pkt* filled in. False
	 * if not packet is available or an error occured (which must be
	 * flagged via Error()).
	 */
	virtual bool ExtractNextPacket(Packet* pkt) = 0;

	/**
	 * Signals that the data of previously extracted packet will no
	 * longer be needed.
	 */
	virtual void DoneWithPacket() = 0;

	/**
	 * Performs the actual filter compilation. This can be overridden to
	 * provide a different implementation of the compilation called by
	 * PrecompileBPFFilter(). This is primarily used by the pcap source
	 * use a different version of BPF_Filter::Compile;
	 *
	 * @param filter the filtering string being compiled.
	 *
	 * @return The compiled filter or nullptr if compilation failed.
	 */
	virtual detail::BPF_Program* CompileFilter(const std::string& filter);

private:
	// Internal helper for ExtractNextPacket().
	bool ExtractNextPacketInternal();

	// IOSource interface implementation.
	void InitSource() override;
	void Done() override;
	void Process() override;
	const char* Tag() override;

	Properties props;

	bool have_packet;
	Packet current_packet;

	// For BPF filtering support.
	std::vector<detail::BPF_Program*> filters;

	std::string errbuf;
	};

	} // namespace zeek::iosource
