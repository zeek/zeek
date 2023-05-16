// See the file "COPYING" in the main distribution directory for copyright.

/**
 * Cookie types that's stored in the HILTI context to provide access to the
 * current analyzer.
 */

#pragma once

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "zeek/Val.h"
#include "zeek/analyzer/Analyzer.h"
#include "zeek/analyzer/protocol/tcp/TCP.h"
#include "zeek/file_analysis/Analyzer.h"
#include "zeek/packet_analysis/Analyzer.h"

namespace zeek::spicy::rt {

namespace cookie {

/** State representing analysis of one file. */
struct FileState {
    FileState(std::string fid) : fid(std::move(fid)) {}
    std::string fid;                      /**< unique Zeek-side file ID */
    std::optional<std::string> mime_type; /**< MIME type, if explicitly set */
};

/**
 * State stored inside protocol/file analyzer cookies retaining file analysis
 * state.
 *
 * Internally, this maintains a stack of state objects representing individual
 * files that are currently in-flight.
 */
class FileStateStack {
public:
    /**
     * Constructor.
     *
     * @param analyzer_id unique ID string representing parent connection/file analyzer
     */
    FileStateStack(std::string analyzer_id) : _analyzer_id(std::move(analyzer_id)) {}

    /**
     * Begins analysis for a new file, pushing a new state object onto the
     * stack.
     */
    FileState* push();

    /** Returns true if the stack is currently empty. */
    bool isEmpty() const { return _stack.empty(); }

    /**
     * Removes an object from the stack.
     *
     * @param fid ID of file to remove state for; no-op if not found
     */
    void remove(const std::string& fid);

    /**
     * Returns a pointer to the state of the most recently pushed file. Must not
     * be called on an empty stack.
     **/
    const FileState* current() const {
        assert(_stack.size());
        return &_stack.back();
    }

    /**
     * Returns the state of a given file currently on the stack.
     *
     * @param fid ID of file to find
     * @returns pointer to the file's state, or null if not found
     */
    const FileState* find(const std::string& fid) const;

private:
    std::vector<FileState> _stack; // stack of files in flight
    std::string _analyzer_id;      // unique ID string of parent analyzer, as passed into ctor
    uint64_t _id_counter = 0;      // counter incremented for each file added to this stack
};

/** State on the current protocol analyzer. */
struct ProtocolAnalyzer {
    analyzer::Analyzer* analyzer = nullptr;                            /**< current analyzer */
    bool is_orig = false;                                              /**< direction of the connection */
    uint64_t num_packets = 0;                                          /**< number of packets seen so far */
    FileStateStack fstate_orig;                                        /**< file analysis state for originator side */
    FileStateStack fstate_resp;                                        /**< file analysis state for responder side */
    std::shared_ptr<packet_analysis::TCP::TCPSessionAdapter> fake_tcp; /**< fake TPC analyzer created internally */
};

/** State on the current file analyzer. */
struct FileAnalyzer {
    file_analysis::Analyzer* analyzer = nullptr; /**< current analyzer */
    uint64_t depth = 0;    /**< recursive depth of file analysis (Spicy-side file analysis only) */
    FileStateStack fstate; /**< file analysis state for nested files */
};

/** State on the current file analyzer. */
struct PacketAnalyzer {
    packet_analysis::Analyzer* analyzer = nullptr; /**< current analyzer */
    Packet* packet = nullptr;                      /**< current packet */
    ValPtr packet_val = nullptr;                   /**< cached "raw_pkt_hdr" val for packet */
    std::optional<uint32_t> next_analyzer;
};

} // namespace cookie

/**
 * Type of state stored in HILTI's execution context during Spicy processing.
 * This is optimized for fast access and small size.
 */
struct Cookie {
    // Exactly one of these pointers is non-null at any time. In that way, the
    // pointers provide the semantics of a tagged union. Internals are bit
    // tricky because the union itself cannot be copied/moved.
    cookie::ProtocolAnalyzer* protocol = nullptr;
    cookie::FileAnalyzer* file = nullptr;
    cookie::PacketAnalyzer* packet = nullptr;

    Cookie(cookie::ProtocolAnalyzer&& c) : data(std::move(c)) { protocol = &data.protocol; }
    Cookie(cookie::FileAnalyzer&& c) : data(std::move(c)) { file = &data.file; }
    Cookie(cookie::PacketAnalyzer&& c) : data(std::move(c)) { packet = &data.packet; }
    Cookie(Cookie&& other) noexcept : data(other.tag(), std::move(other.data)) { _initLike(other); }
    ~Cookie() { _delete(); }

    Cookie& operator=(Cookie&& other) noexcept {
        if ( this == &other )
            return *this;

        _delete();
        _initLike(other);

        new (&data) Data(tag(), std::move(other.data));
        return *this;
    }

    // Cache of values that can be expensive to compute.
    struct {
        ValPtr conn = nullptr;    // valid only for protocol analyzers
        ValPtr is_orig = nullptr; // valid only for protocol analyzers
        bool confirmed = false;   // valid only for protocol analyzers;
    } cache;

    enum Tag { Protocol, File, Packet };

    /** Returns the type of cookie currently stored. */
    Tag tag() const {
        if ( protocol )
            return Tag::Protocol;
        else if ( file )
            return Tag::File;
        else if ( packet )
            return Tag::Packet;
        else
            throw std::runtime_error("invalid cookie");
    }

private:
    union Data {
        cookie::ProtocolAnalyzer protocol;
        cookie::FileAnalyzer file;
        cookie::PacketAnalyzer packet;

        Data(cookie::ProtocolAnalyzer&& protocol) : protocol(std::move(protocol)) {}
        Data(cookie::FileAnalyzer&& file) : file(std::move(file)) {}
        Data(cookie::PacketAnalyzer&& packet) : packet(std::move(packet)) {}
        Data(Tag tag, Data&& other) {
            switch ( tag ) {
                case Tag::Protocol: new (&protocol) cookie::ProtocolAnalyzer(std::move(other.protocol)); break;
                case Tag::File: new (&file) cookie::FileAnalyzer(std::move(other.file)); break;
                case Tag::Packet: new (&packet) cookie::PacketAnalyzer(std::move(other.packet)); break;
            }
        }

        ~Data() {
            // don't delete anything, Cookie is in charge.
        }

        Data(const Data& other) = delete;
        Data& operator=(const Data& other) = delete;
        Data& operator=(Data&& other) = delete;
    } data;

    void _delete() {
        if ( protocol ) {
            data.protocol.~ProtocolAnalyzer();
            protocol = nullptr;
            cache.conn = nullptr;
            cache.is_orig = nullptr;
            cache.confirmed = false;
        }
        else if ( file ) {
            data.file.~FileAnalyzer();
            file = nullptr;
        }
        else if ( packet ) {
            data.packet.~PacketAnalyzer();
            packet = nullptr;
        }
    }

    void _initLike(const Cookie& other) {
        if ( other.protocol ) {
            protocol = &data.protocol;
            cache.confirmed = other.cache.confirmed;
        }

        else if ( other.file )
            file = &data.file;

        else if ( other.packet )
            packet = &data.packet;
    }

    Cookie(const Cookie& other) = delete;
    Cookie& operator=(const Cookie& other) = delete;

    friend inline void swap(Cookie& lhs, Cookie& rhs) {
        Cookie tmp = std::move(lhs);
        lhs = std::move(rhs);
        rhs = std::move(tmp);
    }
};

} // namespace zeek::spicy::rt
