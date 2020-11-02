// See the file "COPYING" in the main distribution directory for copyright.
#pragma once

#include "Manager.h"
#include "Tag.h"
#include <iosource/Packet.h>

namespace zeek::packet_analysis {

/**
 * Main packet analyzer interface.
 */
class Analyzer {
public:
	/**
	 * Constructor.
	 *
	 * @param name The name for the type of analyzer. The name must match
	 * the one the corresponding Component registers.
	 */
	explicit Analyzer(std::string name);

	/**
	 * Constructor.
	 *
	 * @param tag The tag for the type of analyzer. The tag must map to
	 * the name the corresponding Component registers.
	 */
	explicit Analyzer(const Tag& tag);

	/**
	 * Destructor.
	 */
	virtual ~Analyzer() = default;

	/**
	 * Initialize the analyzer. This method is called after the configuration
	 * was read. Derived classes can override this method to implement custom
	 * initialization.
	 * When overriding this methods, always make sure to call the base-class
	 * version to ensure proper initialization.
	 */
	virtual void Initialize();

	/**
	 * Returns the tag associated with the analyzer's type.
	 */
	const Tag GetAnalyzerTag() const;

	/**
	 * Returns a textual description of the analyzer's type. This is
	 * what's passed to the constructor and usually corresponds to the
	 * protocol name, e.g., "ARP".
	 */
	const char* GetAnalyzerName() const;

	/**
	 * Returns true if this analyzer's type matches the name passes in.
	 * This is shortcut for comparing GetAnalyzerName() with the given
	 * name.
	 *
	 * @param name The name to check.
	 */
	bool IsAnalyzer(const char* name);

	/**
	 * Analyzes the given packet. A common case is that the analyzed protocol
	 * encapsulates another protocol, which can be determined by an identifier
	 * in the header. In this case, derived classes may use ForwardPacket() to
	 * forward the payload to the corresponding analyzer.
	 *
	 * @param len The number of bytes passed in. As we move along the chain of
	 * analyzers, this is the number of bytes we have left of the packet to
	 * process.
	 * @param data Pointer to the input to process.
	 * @param packet Object that maintains the packet's meta data.
	 *
	 * @return false if the analysis failed, else true.
	 */
	virtual bool AnalyzePacket(size_t len, const uint8_t* data,
	                           Packet* packet) = 0;

	/**
	 * Dumps out debug information to the \c analyzer debug stream.
	 */
	void DumpDebug() const;

	/**
	 * Adds a protocol to this analyzer's dispatcher.
	 *
	 * @param idenfitier The identifier for the protocol being added.
	 * @param child The analyzer that will be called for the new protocol during
	 * forwarding.
	 */
	void RegisterProtocol(uint32_t identifier, AnalyzerPtr child);

protected:
	friend class Manager;

	/**
	 * Looks up the analyzer for the encapsulated protocol based on the given
	 * identifier.
	 *
	 * @param identifier Identifier for the encapsulated protocol.
	 * @return The analyzer registered for the given identifier. Returns a
	 * nullptr if no analyzer is registered.
	 */
	AnalyzerPtr Lookup(uint32_t identifier) const;

	/**
	 * Returns an analyzer based on a script-land definition.
	 *
	 * @param name The script-land identifier for a PacketAnalyzer::Tag value.
	 * @return The defined analyzer if available, else nullptr.
	 */
	AnalyzerPtr LoadAnalyzer(const std::string& name);

	/**
	 * Returns the module name corresponding to the analyzer, i.e. its script-land
	 * namespace. Configuration values for the analyzer are expected in this module.
	 * @return Analyzer's module name.
	 */
	std::string GetModuleName() const {
		return util::fmt("PacketAnalyzer::%s::", GetAnalyzerName());
	};

	/**
	 * Triggers analysis of the encapsulated packet. The encapsulated protocol
	 * is determined using the given identifier.
	 *
	 * @param packet The packet to analyze.
	 * @param data Reference to the payload pointer into the raw packet.
	 * @param identifier The identifier of the encapsulated protocol.
	 *
	 * @return false if the analysis failed, else true.
	 */
	bool ForwardPacket(size_t len, const uint8_t* data, Packet* packet,
	                   uint32_t identifier) const;

	/**
	 * Triggers default analysis of the encapsulated packet if the default analyzer
	 * is set.
	 *
	 * @param packet The packet to analyze.
	 * @param data Reference to the payload pointer into the raw packet.
	 *
	 * @return false if the analysis failed, else true.
	 */
	bool ForwardPacket(size_t len, const uint8_t* data, Packet* packet) const;

private:
	Tag tag;
	Dispatcher dispatcher;
	AnalyzerPtr default_analyzer = nullptr;

	void Init(const Tag& tag);
};

using AnalyzerPtr = std::shared_ptr<Analyzer>;

}
