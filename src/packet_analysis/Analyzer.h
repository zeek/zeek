// See the file "COPYING" in the main distribution directory for copyright.
#pragma once

#include <set>

#include "zeek/Tag.h"
#include "zeek/iosource/Packet.h"
#include "zeek/packet_analysis/Manager.h"
#include "zeek/session/Session.h"

namespace zeek::packet_analysis
	{

/**
 * Main packet analyzer interface.
 */
class Analyzer
	{
public:
	/**
	 * Constructor.
	 *
	 * @param name The name for the type of analyzer. The name must match
	 * the one the corresponding Component registers.
	 * @param report_unknown_protocols Flag for whether to report unknown
	 * protocols during packet forwarding. This should generally always be
	 * set to true.
	 */
	explicit Analyzer(std::string name, bool report_unknown_protocols = true);

	/**
	 * Constructor.
	 *
	 * @param tag The tag for the type of analyzer. The tag must map to
	 * the name the corresponding Component registers.
	 */
	explicit Analyzer(const zeek::Tag& tag);

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
	const zeek::Tag GetAnalyzerTag() const;

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
	 * Return whether this analyzer is enabled or not.
	 *
	 * @return true if the analyzer is enabled, else false.
	 */
	bool IsEnabled() const { return enabled; }

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
	virtual bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) = 0;

	/**
	 * Dumps out debug information to the \c analyzer debug stream.
	 */
	void DumpDebug() const;

	/**
	 * Adds a protocol to this analyzer's dispatcher.
	 *
	 * @param identifier The identifier for the protocol being added.
	 * @param child The analyzer that will be called for the new protocol during
	 * forwarding.
	 */
	void RegisterProtocol(uint32_t identifier, AnalyzerPtr child);

	/**
	 * Registers an analyzer to use for protocol detection if identifier
	 * matching fails. This will also be preferred over the default analyzer
	 * if one exists.
	 *
	 * @param child The analyzer that will be called for protocol detection.
	 */
	void RegisterProtocolDetection(AnalyzerPtr child) { analyzers_to_detect.insert(child); }

	/**
	 * Detects whether the protocol for an analyzer can be found in the packet
	 * data. Packet analyzers can overload this method to provide any sort of
	 * pattern-matching or byte-value detection against the packet data to
	 * determine whether the packet contains the analyzer's protocol. The
	 * analyzer must also register for the detection in script-land using the
	 * PacketAnalyzer::register_protocol_detection bif method.
	 *
	 * @param len The number of bytes passed in. As we move along the chain of
	 * analyzers, this is the number of bytes we have left of the packet to
	 * process.
	 * @param data Pointer to the input to process.
	 * @param packet Object that maintains the packet's meta data.
	 * @return true if the protocol is detected in the packet data.
	 */
	virtual bool DetectProtocol(size_t len, const uint8_t* data, Packet* packet) { return false; }

	/**
	 * Signals Zeek's protocol detection that the analyzer has recognized
	 * the input to indeed conform to the expected protocol. This should
	 * be called as early as possible during a connection's life-time. It
	 * may turn into \c analyzer_confirmation_info event at the script-layer (but
	 * only once per analyzer for each connection, even if the method is
	 * called multiple times).
	 *
	 * If tag is given, it overrides the analyzer tag passed to the
	 * scripting layer; the default is the one of the analyzer itself.
	 */
	virtual void AnalyzerConfirmation(session::Session* session, zeek::Tag tag = zeek::Tag());

	/**
	 * Signals Zeek's protocol detection that the analyzer has found a
	 * severe protocol violation that could indicate that it's not
	 * parsing the expected protocol. This turns into \c
	 * analyzer_violation_info events at the script-layer (one such event is
	 * raised for each call to this method so that the script-layer can
	 * built up a notion of how prevalent protocol violations are; the
	 * more, the less likely it's the right protocol).
	 *
	 * @param reason A textual description of the error encountered.
	 *
	 * @param data An optional pointer to the malformed data.
	 *
	 * @param len If \a data is given, the length of it.
	 */
	virtual void AnalyzerViolation(const char* reason, session::Session* session,
	                               const char* data = nullptr, int len = 0,
	                               zeek::Tag tag = zeek::Tag());

	/**
	 * Returns true if ProtocolConfirmation() has been called at least
	 * once.
	 */
	bool AnalyzerConfirmed(session::Session* session) const
		{
		return session->AnalyzerState(GetAnalyzerTag()) ==
		       session::AnalyzerConfirmationState::CONFIRMED;
		}
	bool AnalyzerViolated(session::Session* session) const
		{
		return session->AnalyzerState(GetAnalyzerTag()) ==
		       session::AnalyzerConfirmationState::VIOLATED;
		}

	/**
	 * Reports a Weird with the analyzer's name included in the addl field.
	 *
	 * @param name The name of the weird.
	 * @param packet An optional pointer to a packet to be used for additional
	 * information in the weird output.
	 * @param addl An optional string containing additional information about
	 * the weird. If this is passed, the analyzer's name will be prepended to
	 * it before output.
	 */
	void Weird(const char* name, Packet* packet = nullptr, const char* addl = "") const;

protected:
	friend class Component;
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
	 * Enable or disable this analyzer. This is meant for internal use by
	 * manager and component.
	 *
	 * @param value The new enabled value.
	 */
	void SetEnabled(bool value) { enabled = value; }

	/**
	 * Returns the module name corresponding to the analyzer, i.e. its script-land
	 * namespace. Configuration values for the analyzer are expected in this module.
	 * @return Analyzer's module name.
	 */
	std::string GetModuleName() const
		{
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
	bool ForwardPacket(size_t len, const uint8_t* data, Packet* packet, uint32_t identifier) const;

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
	// Internal helper to raise analyzer_confirmation events
	void EnqueueAnalyzerConfirmationInfo(session::Session* session, const zeek::Tag& arg_tag);

	// Remove in v6.1 - internal helper to raise analyzer_confirmation
	void EnqueueAnalyzerConfirmation(session::Session* session, const zeek::Tag& arg_tag);

	// Internal helper to raise analyzer_violation_info
	void EnqueueAnalyzerViolationInfo(session::Session* session, const char* reason,
	                                  const char* data, int len, const zeek::Tag& arg_tag);

	// Remove in v6.1 - internal helper to raise analyzer_violation
	void EnqueueAnalyzerViolation(session::Session* session, const char* reason, const char* data,
	                              int len, const zeek::Tag& arg_tag);

	zeek::Tag tag;
	Dispatcher dispatcher;
	AnalyzerPtr default_analyzer = nullptr;
	bool enabled = true;

	/**
	 * Flag for whether to report unknown protocols in ForwardPacket.
	 */
	bool report_unknown_protocols = true;

	std::set<AnalyzerPtr> analyzers_to_detect;

	void Init(const zeek::Tag& tag);
	};

using AnalyzerPtr = std::shared_ptr<Analyzer>;

	}
