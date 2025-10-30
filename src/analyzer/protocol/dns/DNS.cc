// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/analyzer/protocol/dns/DNS.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <cctype>

#include "zeek/Base64.h"
#include "zeek/Event.h"
#include "zeek/IPAddr.h"
#include "zeek/NetVar.h"
#include "zeek/RunState.h"
#include "zeek/Val.h"
#include "zeek/ZeekString.h"
#include "zeek/analyzer/protocol/dns/events.bif.h"
#include "zeek/session/Manager.h"

namespace {
zeek::StringValPtr extract_char_string(zeek::analyzer::Analyzer* analyzer, const u_char*& data, int& len, int& rdlen) {
    if ( rdlen <= 0 )
        return nullptr;

    uint8_t str_size = data[0];

    --rdlen;
    --len;
    ++data;

    if ( str_size > rdlen ) {
        analyzer->Weird("DNS_TXT_char_str_past_rdlen");
        return nullptr;
    }

    auto rval = zeek::make_intrusive<zeek::StringVal>(str_size, reinterpret_cast<const char*>(data));

    rdlen -= str_size;
    len -= str_size;
    data += str_size;

    return rval;
}
} // namespace

namespace zeek::analyzer::dns {

namespace detail {

// Used for checking whether the connection being parsed comes from NetBIOS,
// since it's similar to DNS but does some things differently.
constexpr int NETBIOS_PORT = 137;

DNS_Interpreter::DNS_Interpreter(analyzer::Analyzer* arg_analyzer) : analyzer(arg_analyzer) {
    is_netbios =
        ntohs(analyzer->Conn()->OrigPort()) == NETBIOS_PORT || ntohs(analyzer->Conn()->RespPort()) == NETBIOS_PORT;
}

void DNS_Interpreter::ParseMessage(const u_char* data, int len, int is_query) {
    // Every packet for every opcode starts with same size header.
    int hdr_len = sizeof(detail::DNS_RawMsgHdr);

    if ( len < hdr_len ) {
        analyzer->Weird("DNS_truncated_len_lt_hdr_len");
        return;
    }

    // The flags section may be different between the different opcodes, but the
    // opcode is always in the same location. Parse out just that part of it here
    // even though it will probably be reparsed later.
    auto* hdr = reinterpret_cast<const detail::DNS_RawMsgHdr*>(data);
    auto flags = ntohs(hdr->flags);
    auto opcode = static_cast<uint16_t>((flags & 0x7800) >> 11);

    // NetBIOS registration and release messages look like regular DNS requests, so parse them as such
    if ( opcode != DNS_OP_QUERY && opcode != DNS_OP_DYNAMIC_UPDATE && ! is_netbios ) {
        analyzer->Weird("DNS_unknown_opcode", util::fmt("%d", opcode));
        analyzer->Conn()->CheckHistory(zeek::session::detail::HIST_UNKNOWN_PKT, 'X');
        return;
    }

    detail::DNS_MsgInfo msg(const_cast<DNS_RawMsgHdr*>(hdr), is_query, is_netbios);

    if ( first_message && msg.QR && is_query == 1 ) {
        is_query = 0;
        msg.is_query = false;

        if ( ! analyzer->Conn()->RespAddr().IsMulticast() )
            analyzer->Conn()->FlipRoles();
    }

    first_message = false;

    if ( dns_message )
        analyzer->EnqueueConnEvent(dns_message, analyzer->ConnVal(), val_mgr->Bool(is_query), msg.BuildHdrVal(),
                                   val_mgr->Count(len));

    // There is a great deal of non-DNS traffic that runs on port 53.
    // This should weed out most of it.
    if ( zeek::detail::dns_max_queries > 0 && msg.qd_zo_count > zeek::detail::dns_max_queries ) {
        analyzer->AnalyzerViolation("DNS_Conn_count_too_large");
        analyzer->Weird("DNS_Conn_count_too_large");
        EndMessage(&msg);
        return;
    }

    const u_char* msg_start = data; // needed for interpreting compression

    data += hdr_len;
    len -= hdr_len;

    if ( msg.is_dynamic_update ) {
        if ( msg.qd_zo_count != 1 ) {
            // dynamic update events should only have a single zone in them.
            analyzer->Weird("DNS_DU_invalid_zone_count", util::fmt("%d", msg.qd_zo_count));
            EndMessage(&msg);
            return;
        }

        // Dynamic update looks like this:
        // 1. A single "zone" that is just the first three fields of an SOA RR. It's
        //    required to be an SOA, so a weird is returned if not.
        // 2. Zero or more "prerequisite" RRs that are required to be true in the zone
        //    before updates take place.
        // 3. Zero or more "update" RRs that are the updates to be made to the zone.
        // 4. Zero or more "additional" RRs that are unrelated to the updates. These are
        //    handled same to the other additional RRs with other op codes.
        if ( ! ParseAnswerHeader(&msg, data, len, msg_start) ) {
            EndMessage(&msg);
            return;
        }

        if ( msg.atype != detail::TYPE_SOA ) {
            analyzer->Weird("DNS_DU_incorrect_zone_type");
            return;
        }

        StringValPtr zname = msg.query_name;
        uint32_t zclass = msg.aclass;

        if ( ! ParseAnswers(&msg, msg.an_pr_count, detail::DNS_PREREQUISITES, data, len, msg_start) ) {
            EndMessage(&msg);
            return;
        }

        if ( ! ParseAnswers(&msg, msg.ns_up_count, detail::DNS_UPDATES, data, len, msg_start) ) {
            EndMessage(&msg);
            return;
        }

        // Send an event if the first three parts parsed correctly, since they're the
        // actual update bits.
        if ( dns_dynamic_update )
            analyzer->EnqueueConnEvent(dns_dynamic_update, analyzer->ConnVal(), msg.BuildHdrVal(), zname,
                                       val_mgr->Count(zclass));
    }
    else {
        if ( ! ParseQuestions(&msg, data, len, msg_start) ) {
            EndMessage(&msg);
            return;
        }

        if ( ! ParseAnswers(&msg, msg.an_pr_count, detail::DNS_ANSWER, data, len, msg_start) ) {
            EndMessage(&msg);
            return;
        }
    }

    analyzer->AnalyzerConfirmation();

    bool skip_auth = (zeek::detail::dns_skip_all_auth != 0);
    bool skip_addl = (zeek::detail::dns_skip_all_addl != 0);
    if ( msg.an_pr_count > 0 ) { // We did an answer, so can potentially skip auth/addl.
        static auto dns_skip_auth = id::find_val<TableVal>("dns_skip_auth");
        static auto dns_skip_addl = id::find_val<TableVal>("dns_skip_addl");
        auto server = make_intrusive<AddrVal>(analyzer->Conn()->RespAddr());

        skip_auth = skip_auth || msg.ns_up_count == 0 || dns_skip_auth->FindOrDefault(server);
        skip_addl = skip_addl || msg.arcount == 0 || dns_skip_addl->FindOrDefault(server);
    }

    if ( skip_auth && skip_addl ) {
        // No point doing further work parsing the message.
        EndMessage(&msg);
        return;
    }

    // Dynamic update doesn't have an authority section.
    if ( ! msg.is_dynamic_update ) {
        msg.skip_event = skip_auth;
        if ( ! ParseAnswers(&msg, msg.ns_up_count, detail::DNS_AUTHORITY, data, len, msg_start) ) {
            EndMessage(&msg);
            return;
        }
    }

    if ( skip_addl ) {
        // No point doing further work parsing the message.
        EndMessage(&msg);
        return;
    }

    msg.skip_event = skip_addl;
    if ( ! ParseAnswers(&msg, msg.arcount, detail::DNS_ADDITIONAL, data, len, msg_start) ) {
        EndMessage(&msg);
        return;
    }

    EndMessage(&msg);
}

void DNS_Interpreter::EndMessage(detail::DNS_MsgInfo* msg) {
    if ( dns_end )
        analyzer->EnqueueConnEvent(dns_end, analyzer->ConnVal(), msg->BuildHdrVal());
}

bool DNS_Interpreter::ParseQuestions(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, const u_char* msg_start) {
    int n = msg->qd_zo_count;

    while ( n > 0 && ParseQuestion(msg, data, len, msg_start) )
        --n;
    return n == 0;
}

bool DNS_Interpreter::ParseAnswers(detail::DNS_MsgInfo* msg, int n, detail::DNS_AnswerType atype, const u_char*& data,
                                   int& len, const u_char* msg_start) {
    msg->answer_type = atype;

    while ( n > 0 && ParseAnswer(msg, data, len, msg_start) )
        --n;

    return n == 0;
}

bool DNS_Interpreter::ParseQuestion(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, const u_char* msg_start) {
    u_char name[513];
    int name_len = sizeof(name) - 1;

    u_char* name_end = ExtractName(data, len, name, name_len, msg_start, false);
    if ( ! name_end )
        return false;

    if ( len < int(sizeof(short)) * 2 ) {
        analyzer->Weird("DNS_truncated_quest_too_short");
        return false;
    }

    EventHandlerPtr dns_event = nullptr;

    if ( msg->QR == 0 )
        dns_event = dns_request;

    else if ( msg->QR == 1 && msg->an_pr_count == 0 && msg->ns_up_count == 0 && msg->arcount == 0 )
        // Service rejected in some fashion, and it won't be reported
        // via a returned RR because there aren't any.
        dns_event = dns_rejected;
    else
        dns_event = dns_query_reply;

    if ( dns_event && ! msg->skip_event ) {
        String* original_name = new String(name, name_end - name, true);

        // Downcase the Name to normalize it
        for ( u_char* np = name; np < name_end; ++np )
            if ( isupper(*np) )
                *np = tolower(*np);

        String* question_name = new String(name, name_end - name, true);

        SendReplyOrRejectEvent(msg, dns_event, data, len, question_name, original_name);
    }
    else {
        // Consume the unused type/class.
        (void)ExtractShort(data, len);
        (void)ExtractShort(data, len);
    }

    return true;
}

bool DNS_Interpreter::ParseAnswerHeader(detail::DNS_MsgInfo* msg, const u_char*& data, int& len,
                                        const u_char* msg_start) {
    u_char name[513];
    int name_len = sizeof(name) - 1;

    u_char* name_end = ExtractName(data, len, name, name_len, msg_start);

    if ( ! name_end )
        return false;

    if ( len < int(sizeof(short)) * 2 ) {
        analyzer->Weird("DNS_truncated_ans_too_short");
        return false;
    }

    // Note that the exact meaning of some of these fields will be
    // re-interpreted by other, more adventurous RR types.

    msg->query_name = make_intrusive<StringVal>(new String(name, name_end - name, true));
    msg->atype = static_cast<detail::RR_Type>(ExtractShort(data, len));
    msg->aclass = ExtractShort(data, len);

    return true;
}

bool DNS_Interpreter::ParseAnswer(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, const u_char* msg_start) {
    if ( ! ParseAnswerHeader(msg, data, len, msg_start) )
        return false;

    msg->ttl = ExtractLong(data, len);

    auto rdlength = ExtractShort(data, len);
    if ( rdlength > len ) {
        analyzer->Weird("DNS_truncated_RR_rdlength_lt_len");
        return false;
    }

    if ( msg->is_dynamic_update ) {
        // Read length and ttl can both be zero for dynamic updates, but only if the class is ANY or NONE.
        if ( rdlength == 0 && msg->aclass != DNS_CLASS_ANY && msg->aclass != DNS_CLASS_NONE ) {
            analyzer->Weird("DNS_zero_rdlength_update");
            return false;
        }
        else if ( msg->ttl == 0 && msg->aclass != DNS_CLASS_ANY && msg->aclass != DNS_CLASS_NONE ) {
            analyzer->Weird("DNS_zero_ttl_update");
            return false;
        }
    }

    if ( rdlength == 0 && len > 0 ) {
        if ( msg->is_dynamic_update )
            // See above for when this isn't allowed.
            return true;

        analyzer->Weird("DNS_zero_rdlength");
        return false;
    }

    bool status;
    switch ( msg->atype ) {
        case detail::TYPE_A: status = ParseRR_A(msg, data, len, rdlength); break;

        case detail::TYPE_A6:
        case detail::TYPE_AAAA: status = ParseRR_AAAA(msg, data, len, rdlength); break;

        case detail::TYPE_NS:
        case detail::TYPE_CNAME:
        case detail::TYPE_PTR: status = ParseRR_Name(msg, data, len, rdlength, msg_start); break;

        case detail::TYPE_SOA: status = ParseRR_SOA(msg, data, len, rdlength, msg_start); break;

        case detail::TYPE_WKS: status = ParseRR_WKS(msg, data, len, rdlength); break;

        case detail::TYPE_HINFO: status = ParseRR_HINFO(msg, data, len, rdlength); break;

        case detail::TYPE_MX: status = ParseRR_MX(msg, data, len, rdlength, msg_start); break;

        case detail::TYPE_TXT: status = ParseRR_TXT(msg, data, len, rdlength, msg_start); break;

        case detail::TYPE_SPF: status = ParseRR_SPF(msg, data, len, rdlength, msg_start); break;

        case detail::TYPE_CAA: status = ParseRR_CAA(msg, data, len, rdlength, msg_start); break;

        case detail::TYPE_NBS: status = ParseRR_NBS(msg, data, len, rdlength, msg_start); break;

        case detail::TYPE_SRV:
            if ( ntohs(analyzer->Conn()->RespPort()) == NETBIOS_PORT ) {
                // This is an NBSTAT (NetBIOS NODE STATUS) record.
                // The SRV RFC reused the value that was already being
                // used for this.
                // We aren't parsing this yet.
                status = true;
            }
            else
                status = ParseRR_SRV(msg, data, len, rdlength, msg_start);

            break;

        case detail::TYPE_NAPTR: status = ParseRR_NAPTR(msg, data, len, rdlength, msg_start); break;

        case detail::TYPE_EDNS: status = ParseRR_EDNS(msg, data, len, rdlength, msg_start); break;

        case detail::TYPE_TKEY: status = ParseRR_TKEY(msg, data, len, rdlength, msg_start); break;

        case detail::TYPE_TSIG: status = ParseRR_TSIG(msg, data, len, rdlength, msg_start); break;

        case detail::TYPE_RRSIG: status = ParseRR_RRSIG(msg, data, len, rdlength, msg_start); break;

        case detail::TYPE_DNSKEY: status = ParseRR_DNSKEY(msg, data, len, rdlength, msg_start); break;

        case detail::TYPE_NSEC: status = ParseRR_NSEC(msg, data, len, rdlength, msg_start); break;

        case detail::TYPE_NSEC3: status = ParseRR_NSEC3(msg, data, len, rdlength, msg_start); break;

        case detail::TYPE_NSEC3PARAM: status = ParseRR_NSEC3PARAM(msg, data, len, rdlength, msg_start); break;

        case detail::TYPE_DS: status = ParseRR_DS(msg, data, len, rdlength, msg_start); break;

        case detail::TYPE_BINDS: status = ParseRR_BINDS(msg, data, len, rdlength, msg_start); break;

        case detail::TYPE_SSHFP: status = ParseRR_SSHFP(msg, data, len, rdlength, msg_start); break;

        case detail::TYPE_LOC: status = ParseRR_LOC(msg, data, len, rdlength, msg_start); break;

        case detail::TYPE_SVCB: status = ParseRR_SVCB(msg, data, len, rdlength, msg_start, TYPE_SVCB); break;

        case detail::TYPE_HTTPS: status = ParseRR_SVCB(msg, data, len, rdlength, msg_start, TYPE_HTTPS); break;

        default:

            if ( dns_unknown_reply && ! msg->skip_event )
                analyzer->EnqueueConnEvent(dns_unknown_reply, analyzer->ConnVal(), msg->BuildHdrVal(),
                                           msg->BuildAnswerVal());

            analyzer->Weird("DNS_RR_unknown_type", util::fmt("%d", msg->atype));
            data += rdlength;
            len -= rdlength;
            status = true;
            break;
    }

    return status;
}

u_char* DNS_Interpreter::ExtractName(const u_char*& data, int& len, u_char* name, int name_len, const u_char* msg_start,
                                     bool downcase) {
    u_char* name_start = name;

    while ( ExtractLabel(data, len, name, name_len, msg_start) )
        ;

    int n = name - name_start;

    if ( n >= 255 )
        analyzer->Weird("DNS_NAME_too_long");

    if ( n >= 2 && name[-1] == '.' ) {
        // Remove trailing dot.
        --name;
        name[0] = 0;
    }

    // Convert labels to lower case for consistency.
    if ( downcase )
        for ( u_char* np = name_start; np < name; ++np )
            if ( isupper(*np) )
                *np = tolower(*np);

    return name;
}

bool DNS_Interpreter::ExtractLabel(const u_char*& data, int& len, u_char*& name, int& name_len,
                                   const u_char* msg_start) {
    if ( len <= 0 )
        return false;

    const u_char* orig_data = data;
    auto label_len = data[0];

    ++data;
    --len;

    if ( len <= 0 )
        return false;

    if ( label_len == 0 )
        // Found terminating label.
        return false;

    // If the label length is 0xc0, this is a pointer to another spot in the packet data.
    if ( (label_len & 0xc0) == 0xc0 ) {
        auto offset = (label_len & ~0xc0) << 8;

        offset |= *data;

        ++data;
        --len;

        if ( offset >= orig_data - msg_start ) {
            // (You'd think that actually the offset should be
            //  at least 6 bytes below our current position:
            //  2 bytes for a non-trivial label, plus 4 bytes for
            //  its class and type, which presumably are between
            //  our current location and the instance of the label.
            //  But actually this turns out not to be the case -
            //  sometimes compression points to compression.)

            analyzer->Weird("DNS_label_forward_compress_offset");
            return false;
        }

        // Recursively resolve name.
        const u_char* recurse_data = msg_start + offset;
        int recurse_max_len = orig_data - recurse_data;

        u_char* name_end = ExtractName(recurse_data, recurse_max_len, name, name_len, msg_start);

        name_len -= name_end - name;
        name = name_end;

        // Returning false here causes the loop in ExtractName to exit.
        return false;
    }

    if ( label_len > len ) {
        analyzer->Weird("DNS_label_len_gt_pkt");
        data += len; // consume the rest of the packet
        len = 0;
        return false;
    }

    if ( label_len > 63 &&
         // NetBIOS name service look ups can use longer labels.
         ntohs(analyzer->Conn()->RespPort()) != NETBIOS_PORT ) {
        analyzer->Weird("DNS_label_too_long");
        return false;
    }

    if ( label_len >= name_len ) {
        analyzer->Weird("DNS_label_len_gt_name_len");
        return false;
    }

    memcpy(name, data, label_len);
    name[label_len] = '.';

    name += label_len + 1;
    name_len -= label_len + 1;

    data += label_len;
    len -= label_len;

    return true;
}

uint8_t DNS_Interpreter::ExtractByte(const u_char*& data, int& len) {
    if ( len < 1 )
        return 0;

    uint8_t val;
    val = data[0];

    ++data;
    --len;

    return val;
}

uint16_t DNS_Interpreter::ExtractShort(const u_char*& data, int& len) {
    if ( len < 2 )
        return 0;

    uint16_t val;

    val = data[0] << 8;

    ++data;
    --len;

    val |= data[0];

    ++data;
    --len;

    return val;
}

uint32_t DNS_Interpreter::ExtractLong(const u_char*& data, int& len) {
    if ( len < 4 )
        return 0;

    uint32_t val;

    val = data[0] << 24;
    val |= data[1] << 16;
    val |= data[2] << 8;
    val |= data[3];

    data += sizeof(val);
    len -= sizeof(val);

    return val;
}

bool DNS_Interpreter::ParseRR_Name(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength,
                                   const u_char* msg_start) {
    const u_char* data_start = data;

    u_char name[513];
    int name_len = sizeof(name) - 1;

    u_char* name_end = ExtractName(data, len, name, name_len, msg_start);
    if ( ! name_end )
        return false;

    if ( data - data_start != rdlength ) {
        analyzer->Weird("DNS_RR_length_mismatch");
    }

    EventHandlerPtr reply_event;
    switch ( msg->atype ) {
        case detail::TYPE_NS: reply_event = dns_NS_reply; break;

        case detail::TYPE_CNAME:
        case detail::TYPE_AAAA:
        case detail::TYPE_A6: reply_event = dns_CNAME_reply; break;

        case detail::TYPE_PTR: reply_event = dns_PTR_reply; break;

        default: analyzer->Conn()->Internal("DNS_RR_bad_name"); reply_event = nullptr;
    }

    if ( reply_event && ! msg->skip_event )
        analyzer->EnqueueConnEvent(reply_event, analyzer->ConnVal(), msg->BuildHdrVal(), msg->BuildAnswerVal(),
                                   make_intrusive<StringVal>(new String(name, name_end - name, true)));

    return true;
}

bool DNS_Interpreter::ParseRR_SOA(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength,
                                  const u_char* msg_start) {
    const u_char* data_start = data;

    u_char mname[513];
    int mname_len = sizeof(mname) - 1;

    u_char* mname_end = ExtractName(data, len, mname, mname_len, msg_start);
    if ( ! mname_end )
        return false;

    u_char rname[513];
    int rname_len = sizeof(rname) - 1;

    u_char* rname_end = ExtractName(data, len, rname, rname_len, msg_start);
    if ( ! rname_end )
        return false;

    if ( len < 20 )
        return false;

    auto serial = ExtractLong(data, len);
    auto refresh = ExtractLong(data, len);
    auto retry = ExtractLong(data, len);
    auto expire = ExtractLong(data, len);
    auto minimum = ExtractLong(data, len);

    if ( data - data_start != rdlength )
        analyzer->Weird("DNS_RR_length_mismatch");

    if ( dns_SOA_reply && ! msg->skip_event ) {
        static auto dns_soa = id::find_type<RecordType>("dns_soa");
        auto r = make_intrusive<RecordVal>(dns_soa);
        r->Assign(0, new String(mname, mname_end - mname, true));
        r->Assign(1, new String(rname, rname_end - rname, true));
        r->Assign(2, serial);
        r->AssignInterval(3, double(refresh));
        r->AssignInterval(4, double(retry));
        r->AssignInterval(5, double(expire));
        r->AssignInterval(6, double(minimum));

        analyzer->EnqueueConnEvent(dns_SOA_reply, analyzer->ConnVal(), msg->BuildHdrVal(), msg->BuildAnswerVal(),
                                   std::move(r));
    }

    return true;
}

bool DNS_Interpreter::ParseRR_MX(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength,
                                 const u_char* msg_start) {
    const u_char* data_start = data;

    auto preference = ExtractShort(data, len);

    u_char name[513];
    int name_len = sizeof(name) - 1;

    u_char* name_end = ExtractName(data, len, name, name_len, msg_start);
    if ( ! name_end )
        return false;

    if ( data - data_start != rdlength )
        analyzer->Weird("DNS_RR_length_mismatch");

    if ( dns_MX_reply && ! msg->skip_event )
        analyzer->EnqueueConnEvent(dns_MX_reply, analyzer->ConnVal(), msg->BuildHdrVal(), msg->BuildAnswerVal(),
                                   make_intrusive<StringVal>(new String(name, name_end - name, true)),
                                   val_mgr->Count(preference));

    return true;
}

bool DNS_Interpreter::ParseRR_NBS(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength,
                                  const u_char* msg_start) {
    data += rdlength;
    len -= rdlength;
    return true;
}

bool DNS_Interpreter::ParseRR_SRV(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength,
                                  const u_char* msg_start) {
    const u_char* data_start = data;

    auto priority = ExtractShort(data, len);
    auto weight = ExtractShort(data, len);
    auto port = ExtractShort(data, len);

    u_char name[513];
    int name_len = sizeof(name) - 1;

    u_char* name_end = ExtractName(data, len, name, name_len, msg_start);
    if ( ! name_end )
        return false;

    if ( data - data_start != rdlength )
        analyzer->Weird("DNS_RR_length_mismatch");

    if ( dns_SRV_reply && ! msg->skip_event )
        analyzer->EnqueueConnEvent(dns_SRV_reply, analyzer->ConnVal(), msg->BuildHdrVal(), msg->BuildAnswerVal(),
                                   make_intrusive<StringVal>(new String(name, name_end - name, true)),
                                   val_mgr->Count(priority), val_mgr->Count(weight), val_mgr->Count(port));

    return true;
}

bool DNS_Interpreter::ParseRR_NAPTR(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength,
                                    const u_char* msg_start) {
    auto order = ExtractShort(data, len);
    auto preference = ExtractShort(data, len);
    rdlength -= 4;

    if ( len <= 0 || rdlength <= 0 ) {
        analyzer->AnalyzerViolation("DNS_NAPTR_too_short");
        return false;
    }

    // These all check rdlength and return nullptr if there's not enough data available.
    auto flags = extract_char_string(analyzer, data, len, rdlength);
    auto service = extract_char_string(analyzer, data, len, rdlength);
    auto regexp = extract_char_string(analyzer, data, len, rdlength);

    // The replacement string is a name. Compression shouldn't be used, but doesn't seem
    // we have a helper that would allow to control this.
    u_char replacement[513];
    int replacement_len = sizeof(replacement) - 1;
    u_char* replacement_end = ExtractName(data, len, replacement, replacement_len, msg_start, false);

    if ( ! flags || ! service || ! regexp || ! replacement_end ) {
        analyzer->AnalyzerViolation("DNS_NAPTR_RR_too_short");
        return false;
    }

    if ( dns_NAPTR_reply && ! msg->skip_event ) {
        static auto dns_naptr_rr = id::find_type<RecordType>("dns_naptr_rr");
        auto r = make_intrusive<RecordVal>(dns_naptr_rr);

        r->Assign(0, order);
        r->Assign(1, preference);
        r->Assign(2, std::move(flags));
        r->Assign(3, std::move(service));
        r->Assign(4, std::move(regexp));
        r->Assign(5, zeek::make_intrusive<StringVal>(new String(replacement, replacement_end - replacement, true)));

        analyzer->EnqueueConnEvent(dns_NAPTR_reply, analyzer->ConnVal(), msg->BuildHdrVal(), msg->BuildAnswerVal(), r);
    }

    return true;
}

bool DNS_Interpreter::ParseRR_EDNS(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength,
                                   const u_char* msg_start) {
    if ( dns_EDNS_addl && ! msg->skip_event )
        analyzer->EnqueueConnEvent(dns_EDNS_addl, analyzer->ConnVal(), msg->BuildHdrVal(), msg->BuildEDNS_Val());

    // parse EDNS options. length has to be at least 4 to parse out the option
    // code and length.
    while ( len >= 4 ) {
        auto option_code = ExtractShort(data, len);
        int option_len = ExtractShort(data, len);
        // check for invalid option length
        if ( (option_len > len) ) {
            break;
        }
        len -= option_len;

        // TODO: Implement additional option codes
        switch ( option_code ) {
            case detail::TYPE_ECS: {
                // must be 4 bytes + variable number of octets for address
                if ( option_len <= 4 ) {
                    analyzer->Weird("EDNS_ECS_invalid_option_len");
                    data += option_len;
                    break;
                }

                detail::EDNS_ECS opt{};
                auto ecs_family = ExtractShort(data, option_len);
                auto source_scope = ExtractShort(data, option_len);
                opt.ecs_src_pfx_len = (source_scope >> 8) & 0xff;
                opt.ecs_scp_pfx_len = source_scope & 0xff;

                // ADDRESS, variable number of octets, contains either an IPv4 or
                // IPv6 address, depending on FAMILY, which MUST be truncated to the
                // number of bits indicated by the SOURCE PREFIX-LENGTH field,
                // padding with 0 bits to pad to the end of the last octet needed.
                if ( ecs_family == L3_IPV4 ) {
                    if ( opt.ecs_src_pfx_len > 32 ) {
                        analyzer->Weird("EDNS_ECS_invalid_addr_v4_prefix",
                                        util::fmt("%" PRIu16 " bits", opt.ecs_src_pfx_len));
                        data += option_len;
                        break;
                    }

                    if ( opt.ecs_src_pfx_len > option_len * 8 ) {
                        analyzer->Weird("EDNS_ECS_invalid_addr_v4", util::fmt("need %" PRIu16 " bits, have %d bits",
                                                                              opt.ecs_src_pfx_len, option_len * 8));
                        data += option_len;
                        break;
                    }

                    opt.ecs_family = make_intrusive<StringVal>("v4");
                    uint32_t addr = 0;
                    uint16_t shift_factor = 3;
                    int bits_left = opt.ecs_src_pfx_len;

                    while ( bits_left > 0 ) {
                        addr |= data[0] << (shift_factor * 8);
                        data++;
                        shift_factor--;
                        option_len--;
                        bits_left -= 8;
                    }

                    addr = htonl(addr);
                    opt.ecs_addr = make_intrusive<AddrVal>(addr);
                }
                else if ( ecs_family == L3_IPV6 ) {
                    if ( opt.ecs_src_pfx_len > 128 ) {
                        analyzer->Weird("EDNS_ECS_invalid_addr_v6_prefix",
                                        util::fmt("%" PRIu16 " bits", opt.ecs_src_pfx_len));
                        data += option_len;
                        break;
                    }

                    if ( opt.ecs_src_pfx_len > option_len * 8 ) {
                        analyzer->Weird("EDNS_ECS_invalid_addr_v6", util::fmt("need %" PRIu16 " bits, have %d bits",
                                                                              opt.ecs_src_pfx_len, option_len * 8));
                        data += option_len;
                        break;
                    }

                    opt.ecs_family = make_intrusive<StringVal>("v6");
                    uint32_t addr[4] = {0};
                    uint16_t shift_factor = 15;
                    int bits_left = opt.ecs_src_pfx_len;
                    int i = 0;

                    while ( bits_left > 0 ) {
                        addr[i / 4] |= data[0] << ((shift_factor % 4) * 8);
                        data++;
                        i++;
                        shift_factor--;
                        option_len--;
                        bits_left -= 8;
                    }

                    for ( uint32_t& a : addr ) {
                        a = htonl(a);
                    }
                    opt.ecs_addr = make_intrusive<AddrVal>(addr);
                }
                else {
                    // non ipv4/ipv6 family address
                    data += option_len;
                    break;
                }

                analyzer->EnqueueConnEvent(dns_EDNS_ecs, analyzer->ConnVal(), msg->BuildHdrVal(),
                                           msg->BuildEDNS_ECS_Val(&opt));
                data += option_len;
                break;
            } // END EDNS ECS

            case TYPE_TCP_KA: {
                EDNS_TCP_KEEPALIVE edns_tcp_keepalive{true, 0};
                if ( option_len == 0 || option_len == 2 ) {
                    // 0 bytes is permitted by RFC 7828, showing that the timeout value is
                    // omitted.
                    if ( option_len == 2 ) {
                        edns_tcp_keepalive.keepalive_timeout = ExtractShort(data, option_len);
                        edns_tcp_keepalive.keepalive_timeout_omitted = false;
                    }

                    if ( analyzer->Conn()->ConnTransport() == TRANSPORT_UDP ) {
                        /*
                         * Based on RFC 7828 (3.2.1/3.2.2), clients and servers MUST NOT
                         * negotiate TCP Keepalive timeout in DNS-over-UDP.
                         */
                        analyzer->Weird("EDNS_TCP_Keepalive_In_UDP");
                    }

                    analyzer->EnqueueConnEvent(dns_EDNS_tcp_keepalive, analyzer->ConnVal(), msg->BuildHdrVal(),
                                               msg->BuildEDNS_TCP_KA_Val(&edns_tcp_keepalive));
                }
                else {
                    // error. MUST BE 0 or 2 bytes. skip
                    data += option_len;
                }
                break;
            } // END EDNS TCP KEEPALIVE

            case TYPE_COOKIE: {
                EDNS_COOKIE cookie{};
                if ( option_len != 8 && ! (option_len >= 16 && option_len <= 40) ) {
                    /*
                     * option length for DNS Cookie must be 8 bytes (with client cookie only)
                     * OR
                     * between 16 bytes to 40 bytes (with an 8 bytes client and an 8 to 32 bytes
                     * server cookie)
                     */
                    data += option_len;
                    break;
                }

                int client_cookie_len = 8;
                int server_cookie_len = option_len - client_cookie_len;

                cookie.client_cookie = ExtractStream(data, client_cookie_len, client_cookie_len);
                cookie.server_cookie = nullptr;

                if ( server_cookie_len >= 8 ) {
                    cookie.server_cookie = ExtractStream(data, server_cookie_len, server_cookie_len);
                }

                analyzer->EnqueueConnEvent(dns_EDNS_cookie, analyzer->ConnVal(), msg->BuildHdrVal(),
                                           msg->BuildEDNS_COOKIE_Val(&cookie));

                break;
            } // END EDNS COOKIE

            default: {
                data += option_len;
                break;
            }
        }
    }

    if ( len > 0 ) {
        analyzer->Weird("EDNS_truncated_option");
        return false;
    }

    return true;
}

void DNS_Interpreter::ExtractOctets(const u_char*& data, int& len, String** p) {
    auto dlen = ExtractShort(data, len);
    dlen = std::min(len, static_cast<int>(dlen));

    if ( p )
        *p = new String(data, dlen, false);

    data += dlen;
    len -= dlen;
}

String* DNS_Interpreter::ExtractStream(const u_char*& data, int& len, int l) {
    l = std::max(l, 0);
    int dlen = std::min(len, l); // Len in bytes of the algorithm use
    auto rval = new String(data, dlen, false);

    data += dlen;
    len -= dlen;
    return rval;
}

bool DNS_Interpreter::ParseRR_TSIG(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength,
                                   const u_char* msg_start) {
    const u_char* data_start = data;
    u_char alg_name[1024];
    int alg_name_len = sizeof(alg_name) - 1;

    u_char* alg_name_end = ExtractName(data, len, alg_name, alg_name_len, msg_start);

    if ( ! alg_name_end )
        return false;

    auto sign_time_sec = ExtractLong(data, len);
    auto sign_time_msec = ExtractShort(data, len);
    auto fudge = ExtractShort(data, len);
    String* request_MAC;
    ExtractOctets(data, len, dns_TSIG_addl ? &request_MAC : nullptr);
    auto orig_id = ExtractShort(data, len);
    auto rr_error = ExtractShort(data, len);
    ExtractOctets(data, len, nullptr); // Other Data

    if ( dns_TSIG_addl ) {
        detail::TSIG_DATA tsig;
        tsig.alg_name = new String(alg_name, alg_name_end - alg_name, true);
        tsig.sig = request_MAC;
        tsig.time_s = sign_time_sec;
        tsig.time_ms = sign_time_msec;
        tsig.fudge = fudge;
        tsig.orig_id = orig_id;
        tsig.rr_error = rr_error;

        analyzer->EnqueueConnEvent(dns_TSIG_addl, analyzer->ConnVal(), msg->BuildHdrVal(), msg->BuildTSIG_Val(&tsig));
    }

    return true;
}

bool DNS_Interpreter::ParseRR_TKEY(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength,
                                   const u_char* msg_start) {
    if ( ! dns_TKEY || msg->skip_event ) {
        data += rdlength;
        len -= rdlength;
        return true;
    }

    if ( len < 16 )
        return false;

    const u_char* data_start = data;
    u_char alg_name[513];
    int alg_name_len = sizeof(alg_name) - 1;

    u_char* alg_name_end = ExtractName(data, len, alg_name, alg_name_len, msg_start);

    if ( ! alg_name_end )
        return false;

    auto inception = ExtractLong(data, len);
    auto expiration = ExtractLong(data, len);
    auto mode = ExtractShort(data, len);
    auto error = ExtractShort(data, len);
    String* key_data;
    ExtractOctets(data, len, dns_TKEY ? &key_data : nullptr);
    ExtractOctets(data, len, nullptr); // Other data

    if ( dns_TKEY ) {
        detail::TKEY_DATA tkey;
        tkey.alg_name = new String(alg_name, int(alg_name_end - alg_name), true);
        tkey.inception = inception;
        tkey.expiration = expiration;
        tkey.mode = mode;
        tkey.error = error;
        tkey.key = key_data;
        analyzer->EnqueueConnEvent(dns_TKEY, analyzer->ConnVal(), msg->BuildHdrVal(), msg->BuildTKEY_Val(&tkey));
    }

    return true;
}

bool DNS_Interpreter::ParseRR_RRSIG(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength,
                                    const u_char* msg_start) {
    if ( ! dns_RRSIG || msg->skip_event ) {
        data += rdlength;
        len -= rdlength;
        return true;
    }

    if ( len < 18 )
        return false;

    auto type_covered = ExtractShort(data, len);
    // split the two bytes for algo and labels extraction
    auto algo_lab = ExtractShort(data, len);
    auto algo = (algo_lab >> 8) & 0xff;
    auto lab = algo_lab & 0xff;

    auto orig_ttl = ExtractLong(data, len);
    auto sign_exp = ExtractLong(data, len);
    auto sign_incp = ExtractLong(data, len);
    auto key_tag = ExtractShort(data, len);

    // implement signer's name with the msg_start offset
    const u_char* data_start = data;
    u_char name[513];
    size_t name_len = sizeof(name) - 1;

    u_char* name_end = ExtractName(data, len, name, name_len, msg_start);
    if ( ! name_end )
        return false;

    int sig_len = rdlength - ((data - data_start) + 18);
    auto dsa = static_cast<detail::DNSSEC_Algo>(algo);
    String* sign = ExtractStream(data, len, sig_len);

    switch ( dsa ) {
        case detail::RSA_MD5: analyzer->Weird("DNSSEC_RRSIG_NotRecommended_ZoneSignAlgo", util::fmt("%d", algo)); break;
        case detail::Diffie_Hellman:
        case detail::DSA_SHA1:
        case detail::Elliptic_Curve:
        case detail::RSA_SHA1:
        case detail::DSA_NSEC3_SHA1:
        case detail::RSA_SHA1_NSEC3_SHA1:
        case detail::RSA_SHA256:
        case detail::RSA_SHA512:
        case detail::GOST_R_34_10_2001:
        case detail::ECDSA_curveP256withSHA256:
        case detail::ECDSA_curveP384withSHA384:
        case detail::Ed25519:
        case detail::Ed448: break;
        case detail::Indirect: analyzer->Weird("DNSSEC_RRSIG_Indirect_ZoneSignAlgo", util::fmt("%d", algo)); break;
        case detail::PrivateDNS: analyzer->Weird("DNSSEC_RRSIG_PrivateDNS_ZoneSignAlgo", util::fmt("%d", algo)); break;
        case detail::PrivateOID: analyzer->Weird("DNSSEC_RRSIG_PrivateOID_ZoneSignAlgo", util::fmt("%d", algo)); break;
        default: analyzer->Weird("DNSSEC_RRSIG_unknown_ZoneSignAlgo", util::fmt("%d", algo)); break;
    }

    if ( dns_RRSIG ) {
        detail::RRSIG_DATA rrsig;
        rrsig.type_covered = type_covered;
        rrsig.algorithm = algo;
        rrsig.labels = lab;
        rrsig.orig_ttl = orig_ttl;
        rrsig.sig_exp = sign_exp;
        rrsig.sig_incep = sign_incp;
        rrsig.key_tag = key_tag;
        rrsig.signer_name = new String(name, name_end - name, true);
        rrsig.signature = sign;

        analyzer->EnqueueConnEvent(dns_RRSIG, analyzer->ConnVal(), msg->BuildHdrVal(), msg->BuildAnswerVal(),
                                   msg->BuildRRSIG_Val(&rrsig));
    }

    return true;
}

bool DNS_Interpreter::ParseRR_DNSKEY(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength,
                                     const u_char* msg_start) {
    if ( ! dns_DNSKEY || msg->skip_event ) {
        data += rdlength;
        len -= rdlength;
        return true;
    }

    if ( len < 4 )
        return false;

    auto dflags = ExtractShort(data, len);
    // split the two bytes for protocol and algorithm extraction
    auto proto_algo = ExtractShort(data, len);
    auto dprotocol = (proto_algo >> 8) & 0xff;
    auto dalgorithm = proto_algo & 0xff;
    auto dsa = static_cast<detail::DNSSEC_Algo>(dalgorithm);
    // Evaluating the size of remaining bytes for Public Key
    String* key = ExtractStream(data, len, rdlength - 4);

    // flags bit  7: zone key
    // flags bit  8: revoked
    // flags bit 15: Secure Entry Point, key signing key
    if ( (dflags & 0xfe7e) != 0 )
        analyzer->Weird("DNSSEC_DNSKEY_Invalid_Flag", util::fmt("%d", dflags));

    // flags bit 7, 8, and 15 all set
    if ( (dflags & 0x0181) == 0x0181 )
        analyzer->Weird("DNSSEC_DNSKEY_Revoked_KSK", util::fmt("%d", dflags));

    if ( dprotocol != 3 )
        analyzer->Weird("DNSSEC_DNSKEY_Invalid_Protocol", util::fmt("%d", dprotocol));

    switch ( dsa ) {
        case detail::RSA_MD5:
            analyzer->Weird("DNSSEC_DNSKEY_NotRecommended_ZoneSignAlgo", util::fmt("%d", dalgorithm));
            break;
        case detail::Diffie_Hellman:
        case detail::DSA_SHA1:
        case detail::Elliptic_Curve:
        case detail::RSA_SHA1:
        case detail::DSA_NSEC3_SHA1:
        case detail::RSA_SHA1_NSEC3_SHA1:
        case detail::RSA_SHA256:
        case detail::RSA_SHA512:
        case detail::GOST_R_34_10_2001:
        case detail::ECDSA_curveP256withSHA256:
        case detail::ECDSA_curveP384withSHA384:
        case detail::Ed25519:
        case detail::Ed448: break;
        case detail::Indirect:
            analyzer->Weird("DNSSEC_DNSKEY_Indirect_ZoneSignAlgo", util::fmt("%d", dalgorithm));
            break;
        case detail::PrivateDNS:
            analyzer->Weird("DNSSEC_DNSKEY_PrivateDNS_ZoneSignAlgo", util::fmt("%d", dalgorithm));
            break;
        case detail::PrivateOID:
            analyzer->Weird("DNSSEC_DNSKEY_PrivateOID_ZoneSignAlgo", util::fmt("%d", dalgorithm));
            break;
        default: analyzer->Weird("DNSSEC_DNSKEY_unknown_ZoneSignAlgo", util::fmt("%d", dalgorithm)); break;
    }

    if ( dns_DNSKEY ) {
        detail::DNSKEY_DATA dnskey;
        dnskey.dflags = dflags;
        dnskey.dalgorithm = dalgorithm;
        dnskey.dprotocol = dprotocol;
        dnskey.public_key = key;

        analyzer->EnqueueConnEvent(dns_DNSKEY, analyzer->ConnVal(), msg->BuildHdrVal(), msg->BuildAnswerVal(),
                                   msg->BuildDNSKEY_Val(&dnskey));
    }

    return true;
}

bool DNS_Interpreter::ParseRR_NSEC(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength,
                                   const u_char* msg_start) {
    if ( ! dns_NSEC || msg->skip_event ) {
        data += rdlength;
        len -= rdlength;
        return true;
    }

    const u_char* data_start = data;
    u_char name[513];
    int name_len = sizeof(name) - 1;

    u_char* name_end = ExtractName(data, len, name, name_len, msg_start);
    if ( ! name_end )
        return false;

    int typebitmaps_len = rdlength - (data - data_start);

    auto char_strings = make_intrusive<VectorVal>(id::string_vec);

    while ( typebitmaps_len > 0 && len > 0 ) {
        auto block_bmlen = ExtractShort(data, len);
        auto win_blck = (block_bmlen >> 8) & 0xff;
        auto bmlen = block_bmlen & 0xff;

        if ( bmlen == 0 ) {
            analyzer->Weird("DNSSEC_NSEC_bitmapLen0", util::fmt("%d", win_blck));
            break;
        }

        String* bitmap = ExtractStream(data, len, bmlen);
        char_strings->Assign(char_strings->Size(), make_intrusive<StringVal>(bitmap));
        typebitmaps_len = typebitmaps_len - (2 + bmlen);
    }

    if ( dns_NSEC )
        analyzer->EnqueueConnEvent(dns_NSEC, analyzer->ConnVal(), msg->BuildHdrVal(), msg->BuildAnswerVal(),
                                   make_intrusive<StringVal>(new String(name, name_end - name, true)),
                                   std::move(char_strings));

    return true;
}

bool DNS_Interpreter::ParseRR_NSEC3(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength,
                                    const u_char* msg_start) {
    if ( ! dns_NSEC3 || msg->skip_event ) {
        data += rdlength;
        len -= rdlength;
        return true;
    }

    if ( len < 6 )
        return false;

    const u_char* data_start = data;
    auto halgo_flags = ExtractShort(data, len);
    auto hash_algo = (halgo_flags >> 8) & 0xff;
    auto nsec_flags = halgo_flags & 0xff;
    auto iter = ExtractShort(data, len);

    uint8_t salt_len = 0;

    if ( len > 0 ) {
        salt_len = data[0];
        ++data;
        --len;
    }

    auto salt_val = ExtractStream(data, len, static_cast<int>(salt_len));

    uint8_t hash_len = 0;

    if ( len > 0 ) {
        hash_len = data[0];
        ++data;
        --len;
    }

    auto hash_val = ExtractStream(data, len, static_cast<int>(hash_len));

    int typebitmaps_len = rdlength - (data - data_start);

    auto char_strings = make_intrusive<VectorVal>(id::string_vec);

    while ( typebitmaps_len > 0 && len > 0 ) {
        auto block_bmlen = ExtractShort(data, len);
        auto win_blck = (block_bmlen >> 8) & 0xff;
        auto bmlen = block_bmlen & 0xff;

        if ( bmlen == 0 ) {
            analyzer->Weird("DNSSEC_NSEC3_bitmapLen0", util::fmt("%d", win_blck));
            break;
        }

        String* bitmap = ExtractStream(data, len, bmlen);
        char_strings->Assign(char_strings->Size(), make_intrusive<StringVal>(bitmap));
        typebitmaps_len = typebitmaps_len - (2 + bmlen);
    }

    if ( dns_NSEC3 ) {
        detail::NSEC3_DATA nsec3;
        nsec3.nsec_flags = nsec_flags;
        nsec3.nsec_hash_algo = hash_algo;
        nsec3.nsec_iter = iter;
        nsec3.nsec_salt_len = salt_len;
        nsec3.nsec_salt = salt_val;
        nsec3.nsec_hlen = hash_len;
        nsec3.nsec_hash = hash_val;
        nsec3.bitmaps = std::move(char_strings);

        analyzer->EnqueueConnEvent(dns_NSEC3, analyzer->ConnVal(), msg->BuildHdrVal(), msg->BuildAnswerVal(),
                                   msg->BuildNSEC3_Val(&nsec3));
    }

    return true;
}

bool DNS_Interpreter::ParseRR_NSEC3PARAM(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength,
                                         const u_char* msg_start) {
    if ( ! dns_NSEC3PARAM || msg->skip_event ) {
        data += rdlength;
        len -= rdlength;
        return true;
    }

    if ( len < 5 )
        return false;

    auto halgo_flags = ExtractShort(data, len);
    auto hash_algo = (halgo_flags >> 8) & 0xff;
    auto nsec_flags = halgo_flags & 0xff;
    auto iter = ExtractShort(data, len);

    uint8_t salt_len = 0;

    if ( len > 0 ) {
        salt_len = data[0];
        ++data;
        --len;
    }

    auto salt_value = ExtractStream(data, len, static_cast<int>(salt_len));

    if ( dns_NSEC3PARAM ) {
        detail::NSEC3PARAM_DATA nsec3param;
        nsec3param.nsec_flags = nsec_flags;
        nsec3param.nsec_hash_algo = hash_algo;
        nsec3param.nsec_iter = iter;
        nsec3param.nsec_salt_len = salt_len;
        nsec3param.nsec_salt = salt_value;

        analyzer->EnqueueConnEvent(dns_NSEC3PARAM, analyzer->ConnVal(), msg->BuildHdrVal(), msg->BuildAnswerVal(),
                                   msg->BuildNSEC3PARAM_Val(&nsec3param));
    }

    return true;
}

bool DNS_Interpreter::ParseRR_DS(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength,
                                 const u_char* msg_start) {
    if ( ! dns_DS || msg->skip_event ) {
        data += rdlength;
        len -= rdlength;
        return true;
    }

    if ( len < 4 )
        return false;

    auto ds_key_tag = ExtractShort(data, len);
    // split the two bytes for algorithm and digest type extraction
    auto ds_algo_dtype = ExtractShort(data, len);
    auto ds_algo = (ds_algo_dtype >> 8) & 0xff;
    auto ds_dtype = ds_algo_dtype & 0xff;
    auto ds_digest_type = static_cast<detail::DNSSEC_Digest>(ds_dtype);
    String* ds_digest = ExtractStream(data, len, rdlength - 4);

    switch ( ds_digest_type ) {
        case detail::SHA1:
        case detail::SHA256:
        case detail::GOST_R_34_11_94:
        case detail::SHA384: break;
        case detail::reserved: analyzer->Weird("DNSSEC_DS_ReservedDigestType", util::fmt("%d", ds_dtype)); break;
        default: analyzer->Weird("DNSSEC_DS_unknown_DigestType", util::fmt("%d", ds_dtype)); break;
    }

    if ( dns_DS ) {
        detail::DS_DATA ds;
        ds.key_tag = ds_key_tag;
        ds.algorithm = ds_algo;
        ds.digest_type = ds_dtype;
        ds.digest_val = ds_digest;

        analyzer->EnqueueConnEvent(dns_DS, analyzer->ConnVal(), msg->BuildHdrVal(), msg->BuildAnswerVal(),
                                   msg->BuildDS_Val(&ds));
    }

    return true;
}

bool DNS_Interpreter::ParseRR_BINDS(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength,
                                    const u_char* msg_start) {
    if ( ! dns_BINDS || msg->skip_event ) {
        data += rdlength;
        len -= rdlength;
        return true;
    }

    if ( len < 5 )
        return false;

    auto algo_keyid_rflag = ExtractLong(data, len);

    auto algo = (algo_keyid_rflag >> 24) & 0xff;
    auto keyid1 = (algo_keyid_rflag >> 16) & 0xff;
    auto keyid2 = (algo_keyid_rflag >> 8) & 0xff;
    auto rmflag = algo_keyid_rflag & 0xff;

    auto keyid = (keyid1 << 8) | keyid2;

    uint8_t completeflag = ExtractByte(data, len);

    if ( dns_BINDS ) {
        detail::BINDS_DATA binds;
        binds.algorithm = algo;
        binds.key_id = keyid;
        binds.removal_flag = rmflag;
        binds.complete_flag = completeflag;

        analyzer->EnqueueConnEvent(dns_BINDS, analyzer->ConnVal(), msg->BuildHdrVal(), msg->BuildAnswerVal(),
                                   msg->BuildBINDS_Val(&binds));
    }

    return true;
}

bool DNS_Interpreter::ParseRR_SSHFP(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength,
                                    const u_char* msg_start) {
    if ( ! dns_SSHFP || msg->skip_event ) {
        data += rdlength;
        len -= rdlength;
        return true;
    }

    if ( len < 2 )
        return false;

    auto algo_fptype = ExtractShort(data, len);
    auto algo = (algo_fptype >> 8) & 0xff;
    auto fptype = algo_fptype & 0xff;

    String* fingerprint = ExtractStream(data, len, rdlength - 2);

    if ( dns_SSHFP ) {
        analyzer->EnqueueConnEvent(dns_SSHFP, analyzer->ConnVal(), msg->BuildHdrVal(), msg->BuildAnswerVal(),
                                   val_mgr->Count(algo), val_mgr->Count(fptype),
                                   make_intrusive<StringVal>(fingerprint));
    }

    return true;
}

bool DNS_Interpreter::ParseRR_LOC(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength,
                                  const u_char* msg_start) {
    if ( ! dns_LOC || msg->skip_event ) {
        data += rdlength;
        len -= rdlength;
        return true;
    }

    if ( len < 15 )
        return false;

    // split the two bytes for version and size extraction
    auto ver_size = ExtractShort(data, len);
    auto version = (ver_size >> 8) & 0xff;
    auto size = ver_size & 0xff;

    // split the two bytes for horizontal and vertical precision extraction
    auto horiz_vert = ExtractShort(data, len);
    auto horiz_pre = (horiz_vert >> 8) & 0xff;
    auto vert_pre = horiz_vert & 0xff;

    auto latitude = ExtractLong(data, len);
    auto longitude = ExtractLong(data, len);
    auto altitude = ExtractLong(data, len);

    if ( version != 0 ) {
        analyzer->Weird("DNS_LOC_version_unrecognized", util::fmt("%d", version));
    }

    if ( dns_LOC ) {
        detail::LOC_DATA loc;
        loc.version = version;
        loc.size = size;
        loc.horiz_pre = horiz_pre;
        loc.vert_pre = vert_pre;
        loc.latitude = latitude;
        loc.longitude = longitude;
        loc.altitude = altitude;

        analyzer->EnqueueConnEvent(dns_LOC, analyzer->ConnVal(), msg->BuildHdrVal(), msg->BuildAnswerVal(),
                                   msg->BuildLOC_Val(&loc));
    }

    return true;
}

bool DNS_Interpreter::ParseRR_A(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength) {
    if ( rdlength != 4 ) {
        analyzer->Weird("DNS_RR_bad_length");
        return false;
    }

    auto addr = ExtractLong(data, len);

    if ( dns_A_reply && ! msg->skip_event )
        analyzer->EnqueueConnEvent(dns_A_reply, analyzer->ConnVal(), msg->BuildHdrVal(), msg->BuildAnswerVal(),
                                   make_intrusive<AddrVal>(htonl(addr)));

    return true;
}

bool DNS_Interpreter::ParseRR_AAAA(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength) {
    uint32_t addr[4];

    // Intentionally leaving this as a normal loop because it's more descriptive.
    // NOLINTNEXTLINE(modernize-loop-convert)
    for ( size_t i = 0; i < 4; i++ ) {
        addr[i] = htonl(ExtractLong(data, len));

        if ( len < 0 ) {
            if ( msg->atype == detail::TYPE_AAAA )
                analyzer->Weird("DNS_AAAA_neg_length");
            else
                analyzer->Weird("DNS_A6_neg_length");
            return false;
        }
    }

    EventHandlerPtr event;
    if ( msg->atype == detail::TYPE_AAAA )
        event = dns_AAAA_reply;
    else
        event = dns_A6_reply;

    if ( event && ! msg->skip_event )
        analyzer->EnqueueConnEvent(event, analyzer->ConnVal(), msg->BuildHdrVal(), msg->BuildAnswerVal(),
                                   make_intrusive<AddrVal>(addr));

    return true;
}

bool DNS_Interpreter::ParseRR_WKS(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength) {
    if ( ! dns_WKS_reply || msg->skip_event ) {
        data += rdlength;
        len -= rdlength;
        return true;
    }

    // TODO: Pass the ports as parameters to the event
    analyzer->EnqueueConnEvent(dns_WKS_reply, analyzer->ConnVal(), msg->BuildHdrVal(), msg->BuildAnswerVal());

    // TODO: Return a status which reflects if the port parameters were successfully parsed
    return true;
}

bool DNS_Interpreter::ParseRR_HINFO(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength) {
    if ( ! dns_HINFO_reply || msg->skip_event ) {
        data += rdlength;
        len -= rdlength;
        return true;
    }

    auto cpu = extract_char_string(analyzer, data, len, rdlength);
    auto os = extract_char_string(analyzer, data, len, rdlength);

    analyzer->EnqueueConnEvent(dns_HINFO_reply, analyzer->ConnVal(), msg->BuildHdrVal(), msg->BuildAnswerVal(), cpu,
                               os);

    return rdlength == 0;
}

bool DNS_Interpreter::ParseRR_TXT(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength,
                                  const u_char* msg_start) {
    if ( ! dns_TXT_reply || msg->skip_event ) {
        data += rdlength;
        len -= rdlength;
        return true;
    }

    auto char_strings = make_intrusive<VectorVal>(id::string_vec);
    StringValPtr char_string;

    while ( (char_string = extract_char_string(analyzer, data, len, rdlength)) )
        char_strings->Assign(char_strings->Size(), std::move(char_string));

    if ( dns_TXT_reply )
        analyzer->EnqueueConnEvent(dns_TXT_reply, analyzer->ConnVal(), msg->BuildHdrVal(), msg->BuildAnswerVal(),
                                   std::move(char_strings));

    return rdlength == 0;
}

bool DNS_Interpreter::ParseRR_SPF(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength,
                                  const u_char* msg_start) {
    if ( ! dns_SPF_reply || msg->skip_event ) {
        data += rdlength;
        len -= rdlength;
        return true;
    }

    auto char_strings = make_intrusive<VectorVal>(id::string_vec);
    StringValPtr char_string;

    while ( (char_string = extract_char_string(analyzer, data, len, rdlength)) )
        char_strings->Assign(char_strings->Size(), std::move(char_string));

    if ( dns_SPF_reply )
        analyzer->EnqueueConnEvent(dns_SPF_reply, analyzer->ConnVal(), msg->BuildHdrVal(), msg->BuildAnswerVal(),
                                   std::move(char_strings));

    return rdlength == 0;
}

bool DNS_Interpreter::ParseRR_CAA(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength,
                                  const u_char* msg_start) {
    if ( ! dns_CAA_reply || msg->skip_event ) {
        data += rdlength;
        len -= rdlength;
        return true;
    }

    auto flags = ExtractShort(data, len);
    auto tagLen = flags & 0xff;
    flags >>= 8;
    rdlength -= 2;
    if ( static_cast<int>(tagLen) >= rdlength ) {
        analyzer->Weird("DNS_CAA_char_str_past_rdlen");
        return false;
    }
    String* tag = new String(data, tagLen, true);
    len -= tagLen;
    data += tagLen;
    rdlength -= tagLen;
    String* value = new String(data, rdlength, false);

    len -= value->Len();
    data += value->Len();
    rdlength -= value->Len();

    if ( dns_CAA_reply )
        analyzer->EnqueueConnEvent(dns_CAA_reply, analyzer->ConnVal(), msg->BuildHdrVal(), msg->BuildAnswerVal(),
                                   val_mgr->Count(flags), make_intrusive<StringVal>(tag),
                                   make_intrusive<StringVal>(value));
    else {
        delete tag;
        delete value;
    }

    return rdlength == 0;
}

VectorValPtr DNS_Interpreter::Parse_SvcParams(const u_char*& data, int& len, int svc_params_len) {
    static auto dns_svcb_param_vec = id::find_type<VectorType>("dns_svcb_param_vec");
    auto svc_params = make_intrusive<VectorVal>(dns_svcb_param_vec);

    // Each service parameter is at least four bytes, two for key and value length each.
    while ( svc_params_len >= 4 ) {
        static auto dns_svcb_param = id::find_type<RecordType>("dns_svcb_param");
        auto svc_param = make_intrusive<RecordVal>(dns_svcb_param);

        auto key = ExtractShort(data, len);
        auto value_len = ExtractShort(data, len);
        int item_len_parsed = 0;
        svc_params_len -= 4;

        if ( value_len > svc_params_len ) {
            analyzer->Weird("DNS_SVCB_param_value_toobig", util::fmt("%d capped to %d", value_len, svc_params_len));
            value_len = svc_params_len;
            goto malformed;
        }

        svc_param->Assign(0, zeek::val_mgr->Count(key));

        switch ( key ) {
            case detail::mandatory: // list of keys
            {
                if ( value_len == 0 || value_len % 2 != 0 ) {
                    analyzer->Weird("DNS_SVCB_mandatory_length_invalid");
                    goto malformed;
                }

                auto mandatory = make_intrusive<VectorVal>(id::index_vec);

                while ( item_len_parsed + 2 <= value_len ) {
                    mandatory->Append(zeek::val_mgr->Count(ExtractShort(data, len)));
                    item_len_parsed += 2;
                }

                svc_param->Assign(1, std::move(mandatory));
                break;
            }

            case detail::alpn: // list of length-prefixed (1 octet) ALPN IDs
            {
                auto alpn = make_intrusive<VectorVal>(id::string_vec);

                while ( item_len_parsed + 2 < value_len ) {
                    auto alpn_len = ExtractByte(data, len);
                    item_len_parsed += 1;

                    if ( alpn_len == 0 || alpn_len > 255 || alpn_len + item_len_parsed > value_len ) {
                        // Account for already consumed data first.
                        value_len -= item_len_parsed;
                        analyzer->Weird("DNS_SVCB_alpn_length_invalid");
                        goto malformed;
                    }

                    alpn->Append(zeek::make_intrusive<zeek::StringVal>(alpn_len, reinterpret_cast<const char*>(data)));
                    data += alpn_len;
                    len -= alpn_len;
                    item_len_parsed += alpn_len;
                }

                if ( alpn->Size() > 0 )
                    svc_param->Assign(2, std::move(alpn));
                break;
            }

            case detail::no_default_alpn:
                if ( value_len > 0 ) {
                    analyzer->Weird("DNS_SVCB_nodefaultalpn_value");
                    goto malformed;
                }
                break;

            case detail::port: // port
                if ( value_len != 2 ) {
                    analyzer->Weird("DNS_SVCB_port_length_invalid");
                    break;
                }

                svc_param->Assign(3, zeek::val_mgr->Count(ExtractShort(data, len)));
                item_len_parsed += 2;
                break;

            case detail::ipv4hint: // list of IPs
            case detail::ipv6hint: // list of IPs
            {
                const bool is_ipv4 = key == detail::ipv4hint;
                const int addr_len = is_ipv4 ? 4 : 16;

                if ( value_len % addr_len != 0 ) {
                    analyzer->Weird("DNS_SVCB_hint_length_invalid");
                    goto malformed;
                }

                static auto addr_vec = id::find_type<VectorType>("addr_vec");
                auto hint = make_intrusive<VectorVal>(addr_vec);

                while ( item_len_parsed + addr_len <= value_len ) {
                    const auto addr = zeek::IPAddr(is_ipv4 ? IPv4 : IPv6, reinterpret_cast<const uint32_t*>(data),
                                                   zeek::IPAddr::Network);
                    hint->Append(zeek::make_intrusive<zeek::AddrVal>(addr));

                    data += addr_len;
                    len -= addr_len;
                    item_len_parsed += addr_len;
                }

                if ( hint->Size() > 0 )
                    svc_param->Assign(4, std::move(hint));
                break;
            }

            case detail::ech: // ECHConfigList
            {
                const String* ech = ExtractStream(data, len, value_len);
                item_len_parsed += value_len;

                // Convert binary blob to presentation format.
                String* b64 = zeek::detail::encode_base64(ech, nullptr, analyzer->Conn());
                delete ech;

                svc_param->Assign(5, zeek::make_intrusive<zeek::StringVal>(b64));
                break;
            }

            default:
                analyzer->Weird("DNS_SVCB_key_reserved_or_invalid");
            malformed:
                svc_param->Assign(6, zeek::make_intrusive<StringVal>(ExtractStream(data, len, value_len)));
                item_len_parsed += value_len;
                break;
        }

        svc_params->Append(std::move(svc_param));
        svc_params_len -= value_len;
    }

    return svc_params;
}

/**
 * https://datatracker.ietf.org/doc/html/rfc9460#name-rdata-wire-format
 */
bool DNS_Interpreter::ParseRR_SVCB(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength,
                                   const u_char* msg_start, const RR_Type& svcb_type) {
    const u_char* data_start = data;
    // the smallest SVCB/HTTPS rr is 3 bytes:
    // the first 2 bytes are for the svc priority, and the third byte is root (0x0)
    if ( len < 3 ) {
        analyzer->Weird("DNS_SVCB_wrong_length");
        return false;
    }

    auto svc_priority = ExtractShort(data, len);

    u_char target_name[513];
    int name_len = sizeof(target_name) - 1;
    u_char* name_end = ExtractName(data, len, target_name, name_len, msg_start, false);
    if ( ! name_end )
        return false;

    // target name can be root - in this case the alternative endpoint is
    // qname itself. make sure that we print "." instead of an empty string
    if ( name_end - target_name == 0 ) {
        target_name[0] = '.';
        target_name[1] = '\0';
        name_end = target_name + 1;
    }

    std::ptrdiff_t parsed_bytes = data - data_start;
    int svc_params_len = rdlength - parsed_bytes;
    VectorValPtr svc_params = nullptr;

    if ( svc_params_len > 0 ) {
        if ( svc_priority == 0 )
            analyzer->Weird("DNS_SVCB_aliasmode_with_params");

        svc_params = Parse_SvcParams(data, len, svc_params_len);
    }

    SVCB_DATA svcb_data = {svc_priority,
                           make_intrusive<StringVal>(new String(target_name, name_end - target_name, true)),
                           std::move(svc_params)};

    analyzer->EnqueueConnEvent(svcb_type == detail::TYPE_SVCB ? dns_SVCB : dns_HTTPS, analyzer->ConnVal(),
                               msg->BuildHdrVal(), msg->BuildAnswerVal(), msg->BuildSVCB_Val(svcb_data));
    return true;
}

void DNS_Interpreter::SendReplyOrRejectEvent(detail::DNS_MsgInfo* msg, EventHandlerPtr event, const u_char*& data,
                                             int& len, String* question_name, String* original_name) {
    auto qtype = static_cast<detail::RR_Type>(ExtractShort(data, len));
    auto qclass = ExtractShort(data, len);

    assert(event);

    analyzer->EnqueueConnEvent(event, analyzer->ConnVal(), msg->BuildHdrVal(), make_intrusive<StringVal>(question_name),
                               val_mgr->Count(qtype), val_mgr->Count(qclass), make_intrusive<StringVal>(original_name));
}

DNS_MsgInfo::DNS_MsgInfo(DNS_RawMsgHdr* hdr, bool arg_is_query, bool arg_is_netbios)
    : is_query(arg_is_query), is_netbios(arg_is_netbios) {
    // ### Need to fix alignment if hdr is misaligned (not on a short boundary).
    uint16_t flags = ntohs(hdr->flags);

    QR = (flags & 0x8000) != 0;
    opcode = (flags & 0x7800) >> 11;
    AA = (flags & 0x0400) != 0;
    TC = (flags & 0x0200) != 0;
    RD = (flags & 0x0100) != 0;
    RA = (flags & 0x0080) != 0;
    Z = (flags & 0x0070) >> 4;
    AD = (flags & 0x0020) >> 5;
    CD = (flags & 0x0010) >> 4;
    rcode = (flags & 0x000f);

    qd_zo_count = ntohs(hdr->qd_zo_count);
    an_pr_count = ntohs(hdr->an_pr_count);
    ns_up_count = ntohs(hdr->ns_up_count);
    arcount = ntohs(hdr->arcount);

    id = ntohs(hdr->id);
    is_dynamic_update = (opcode == DNS_OP_DYNAMIC_UPDATE && ! is_netbios);
}

RecordValPtr DNS_MsgInfo::BuildHdrVal() {
    static auto dns_msg = id::find_type<RecordType>("dns_msg");
    auto r = make_intrusive<RecordVal>(dns_msg);

    r->Assign(0, id);
    r->Assign(1, opcode);
    r->Assign(2, rcode);
    r->Assign(3, static_cast<bool>(QR));
    r->Assign(4, static_cast<bool>(AA));
    r->Assign(5, static_cast<bool>(TC));
    r->Assign(6, static_cast<bool>(RD));
    r->Assign(7, static_cast<bool>(RA));
    r->Assign(8, Z);
    r->Assign(9, static_cast<bool>(AD));
    r->Assign(10, static_cast<bool>(CD));
    r->Assign(11, qd_zo_count);
    r->Assign(12, an_pr_count);
    r->Assign(13, ns_up_count);
    r->Assign(14, arcount);
    r->Assign(15, is_netbios);

    return r;
}

RecordValPtr DNS_MsgInfo::BuildAnswerVal() {
    static auto dns_answer = id::find_type<RecordType>("dns_answer");
    auto r = make_intrusive<RecordVal>(dns_answer);

    r->Assign(0, answer_type);
    r->Assign(1, query_name);
    r->Assign(2, atype);
    r->Assign(3, aclass);
    r->AssignInterval(4, double(ttl));

    return r;
}

RecordValPtr DNS_MsgInfo::BuildEDNS_Val() {
    // We have to treat the additional record type in EDNS differently
    // than a regular resource record.
    static auto dns_edns_additional = id::find_type<RecordType>("dns_edns_additional");
    auto r = make_intrusive<RecordVal>(dns_edns_additional);

    r->Assign(0, query_name);
    r->Assign(1, answer_type);

    // type = 0x29 or 41 = EDNS
    r->Assign(2, atype);

    // sender's UDP payload size, per RFC 2671 4.3
    r->Assign(3, aclass);

    // Need to break the TTL field into three components:
    // initial: [------------- ttl (32) ---------------------]
    // after:   [ ext rcode (8)][ver # (8)][   Z field (16)  ]

    uint32_t ercode = (ttl >> 24) & 0xff;
    uint32_t version = (ttl >> 16) & 0xff;
    // uint32_t DO = ttl & 0x8000;	// "DNSSEC OK" - RFC 3225
    uint32_t z = ttl & 0xffff;

    uint32_t return_error = (ercode << 4) | rcode;

    r->Assign(4, return_error);
    r->Assign(5, version);
    r->Assign(6, z);
    r->AssignInterval(7, double(ttl));
    r->Assign(8, is_query);

    return r;
}

RecordValPtr DNS_MsgInfo::BuildEDNS_ECS_Val(struct EDNS_ECS* opt) {
    static auto dns_edns_ecs = id::find_type<RecordType>("dns_edns_ecs");
    auto r = make_intrusive<RecordVal>(dns_edns_ecs);

    r->Assign(0, opt->ecs_family);
    r->Assign(1, opt->ecs_src_pfx_len);
    r->Assign(2, opt->ecs_scp_pfx_len);
    r->Assign(3, opt->ecs_addr);

    return r;
}

RecordValPtr DNS_MsgInfo::BuildEDNS_TCP_KA_Val(struct EDNS_TCP_KEEPALIVE* opt) {
    static auto dns_edns_tcp_keepalive = id::find_type<RecordType>("dns_edns_tcp_keepalive");
    auto r = make_intrusive<RecordVal>(dns_edns_tcp_keepalive);

    r->Assign(0, opt->keepalive_timeout_omitted);
    r->Assign(1, opt->keepalive_timeout);

    return r;
}

RecordValPtr DNS_MsgInfo::BuildEDNS_COOKIE_Val(struct EDNS_COOKIE* opt) {
    static auto dns_edns_cookie = id::find_type<RecordType>("dns_edns_cookie");
    auto r = make_intrusive<RecordVal>(dns_edns_cookie);

    r->Assign(0, opt->client_cookie);
    if ( opt->server_cookie != nullptr ) {
        r->Assign(1, opt->server_cookie);
    }

    return r;
}

RecordValPtr DNS_MsgInfo::BuildTKEY_Val(struct TKEY_DATA* tkey) {
    static auto dns_tkey = id::find_type<RecordType>("dns_tkey");
    auto r = make_intrusive<RecordVal>(dns_tkey);

    r->Assign(0, query_name);
    r->Assign(1, answer_type);
    r->Assign(2, tkey->alg_name);
    r->AssignTime(3, static_cast<double>(tkey->inception));
    r->AssignTime(4, static_cast<double>(tkey->expiration));
    r->Assign(5, static_cast<uint16_t>(tkey->mode));
    r->Assign(6, static_cast<uint16_t>(tkey->error));
    r->Assign(7, tkey->key);
    r->Assign(8, is_query);

    return r;
}

RecordValPtr DNS_MsgInfo::BuildTSIG_Val(struct TSIG_DATA* tsig) {
    static auto dns_tsig_additional = id::find_type<RecordType>("dns_tsig_additional");
    auto r = make_intrusive<RecordVal>(dns_tsig_additional);
    double rtime = tsig->time_s + tsig->time_ms / 1000.0;

    // r->Assign(0, answer_type);
    r->Assign(0, query_name);
    r->Assign(1, answer_type);
    r->Assign(2, tsig->alg_name);
    r->Assign(3, tsig->sig);
    r->AssignTime(4, rtime);
    r->AssignTime(5, double(tsig->fudge));
    r->Assign(6, tsig->orig_id);
    r->Assign(7, tsig->rr_error);
    r->Assign(8, is_query);

    return r;
}

RecordValPtr DNS_MsgInfo::BuildRRSIG_Val(RRSIG_DATA* rrsig) {
    static auto dns_rrsig_rr = id::find_type<RecordType>("dns_rrsig_rr");
    auto r = make_intrusive<RecordVal>(dns_rrsig_rr);

    r->Assign(0, query_name);
    r->Assign(1, answer_type);
    r->Assign(2, rrsig->type_covered);
    r->Assign(3, rrsig->algorithm);
    r->Assign(4, rrsig->labels);
    r->AssignInterval(5, double(rrsig->orig_ttl));
    r->AssignTime(6, double(rrsig->sig_exp));
    r->AssignTime(7, double(rrsig->sig_incep));
    r->Assign(8, rrsig->key_tag);
    r->Assign(9, rrsig->signer_name);
    r->Assign(10, rrsig->signature);
    r->Assign(11, is_query);

    return r;
}

RecordValPtr DNS_MsgInfo::BuildDNSKEY_Val(DNSKEY_DATA* dnskey) {
    static auto dns_dnskey_rr = id::find_type<RecordType>("dns_dnskey_rr");
    auto r = make_intrusive<RecordVal>(dns_dnskey_rr);

    r->Assign(0, query_name);
    r->Assign(1, answer_type);
    r->Assign(2, dnskey->dflags);
    r->Assign(3, dnskey->dprotocol);
    r->Assign(4, dnskey->dalgorithm);
    r->Assign(5, dnskey->public_key);
    r->Assign(6, is_query);

    return r;
}

RecordValPtr DNS_MsgInfo::BuildNSEC3_Val(NSEC3_DATA* nsec3) {
    static auto dns_nsec3_rr = id::find_type<RecordType>("dns_nsec3_rr");
    auto r = make_intrusive<RecordVal>(dns_nsec3_rr);

    r->Assign(0, query_name);
    r->Assign(1, answer_type);
    r->Assign(2, nsec3->nsec_flags);
    r->Assign(3, nsec3->nsec_hash_algo);
    r->Assign(4, nsec3->nsec_iter);
    r->Assign(5, nsec3->nsec_salt_len);
    r->Assign(6, nsec3->nsec_salt);
    r->Assign(7, nsec3->nsec_hlen);
    r->Assign(8, nsec3->nsec_hash);
    r->Assign(9, std::move(nsec3->bitmaps));
    r->Assign(10, is_query);

    return r;
}

RecordValPtr DNS_MsgInfo::BuildNSEC3PARAM_Val(NSEC3PARAM_DATA* nsec3param) {
    static auto dns_nsec3param_rr = id::find_type<RecordType>("dns_nsec3param_rr");
    auto r = make_intrusive<RecordVal>(dns_nsec3param_rr);

    r->Assign(0, query_name);
    r->Assign(1, answer_type);
    r->Assign(2, nsec3param->nsec_flags);
    r->Assign(3, nsec3param->nsec_hash_algo);
    r->Assign(4, nsec3param->nsec_iter);
    r->Assign(5, nsec3param->nsec_salt_len);
    r->Assign(6, nsec3param->nsec_salt);
    r->Assign(7, is_query);

    return r;
}

RecordValPtr DNS_MsgInfo::BuildDS_Val(DS_DATA* ds) {
    static auto dns_ds_rr = id::find_type<RecordType>("dns_ds_rr");
    auto r = make_intrusive<RecordVal>(dns_ds_rr);

    r->Assign(0, query_name);
    r->Assign(1, answer_type);
    r->Assign(2, ds->key_tag);
    r->Assign(3, ds->algorithm);
    r->Assign(4, ds->digest_type);
    r->Assign(5, ds->digest_val);
    r->Assign(6, is_query);

    return r;
}

RecordValPtr DNS_MsgInfo::BuildBINDS_Val(BINDS_DATA* binds) {
    static auto dns_binds_rr = id::find_type<RecordType>("dns_binds_rr");
    auto r = make_intrusive<RecordVal>(dns_binds_rr);

    r->Assign(0, query_name);
    r->Assign(1, answer_type);
    r->Assign(2, binds->algorithm);
    r->Assign(3, binds->key_id);
    r->Assign(4, binds->removal_flag);
    r->Assign(5, binds->complete_flag);
    r->Assign(6, is_query);

    return r;
}

RecordValPtr DNS_MsgInfo::BuildLOC_Val(LOC_DATA* loc) {
    static auto dns_loc_rr = id::find_type<RecordType>("dns_loc_rr");
    auto r = make_intrusive<RecordVal>(dns_loc_rr);

    r->Assign(0, query_name);
    r->Assign(1, answer_type);
    r->Assign(2, loc->version);
    r->Assign(3, loc->size);
    r->Assign(4, loc->horiz_pre);
    r->Assign(5, loc->vert_pre);
    r->Assign(6, static_cast<uint64_t>(loc->latitude));
    r->Assign(7, static_cast<uint64_t>(loc->longitude));
    r->Assign(8, static_cast<uint64_t>(loc->altitude));
    r->Assign(9, is_query);

    return r;
}

RecordValPtr DNS_MsgInfo::BuildSVCB_Val(const SVCB_DATA& svcb) {
    static auto dns_svcb_rr = id::find_type<RecordType>("dns_svcb_rr");
    auto r = make_intrusive<RecordVal>(dns_svcb_rr);

    r->Assign(0, svcb.svc_priority);
    r->Assign(1, svcb.target_name);
    if ( svcb.svc_params )
        r->Assign(2, svcb.svc_params);

    return r;
}

} // namespace detail

Contents_DNS::Contents_DNS(Connection* conn, bool orig, detail::DNS_Interpreter* arg_interp)
    : analyzer::tcp::TCP_SupportAnalyzer("CONTENTS_DNS", conn, orig) {
    interp = arg_interp;

    msg_buf = nullptr;
    buf_n = buf_len = msg_size = 0;
    state = detail::DNS_LEN_HI;
}

Contents_DNS::~Contents_DNS() { free(msg_buf); }

void Contents_DNS::Flush() {
    if ( buf_n > 0 ) { // Deliver partial message.
        // '2' here means whether it's a query is unknown.
        interp->ParseMessage(msg_buf, buf_n, 2);
        msg_size = 0;
    }
}

void Contents_DNS::DeliverStream(int len, const u_char* data, bool orig) {
    while ( len > 0 )
        ProcessChunk(len, data, orig);
}

void Contents_DNS::ProcessChunk(int& len, const u_char*& data, bool orig) {
    if ( state == detail::DNS_LEN_HI ) {
        msg_size = (*data) << 8;
        state = detail::DNS_LEN_LO;

        ++data;
        --len;

        if ( len == 0 )
            return;
    }

    if ( state == detail::DNS_LEN_LO ) {
        msg_size += *data;
        state = detail::DNS_MESSAGE_BUFFER;

        buf_n = 0;

        if ( msg_buf ) {
            if ( buf_len < msg_size ) {
                buf_len = msg_size;
                msg_buf = reinterpret_cast<u_char*>(util::safe_realloc((void*)msg_buf, buf_len));
            }
        }
        else {
            buf_len = msg_size;
            msg_buf = reinterpret_cast<u_char*>(util::safe_malloc(buf_len));
        }

        ++data;
        --len;

        if ( len == 0 )
            return;
    }

    if ( state != detail::DNS_MESSAGE_BUFFER )
        Conn()->Internal("state inconsistency in Contents_DNS::DeliverStream");

    int n;
    for ( n = 0; buf_n < msg_size && n < len; ++n )
        msg_buf[buf_n++] = data[n];

    data += n;
    len -= n;

    if ( buf_n < msg_size )
        // Haven't filled up the message buffer yet, no more to do.
        return;

    ForwardPacket(msg_size, msg_buf, orig, -1, nullptr, 0);

    buf_n = 0;
    state = detail::DNS_LEN_HI;
}

DNS_Analyzer::DNS_Analyzer(Connection* conn) : analyzer::tcp::TCP_ApplicationAnalyzer("DNS", conn) {
    interp = new detail::DNS_Interpreter(this);
    contents_dns_orig = contents_dns_resp = nullptr;

    if ( Conn()->ConnTransport() == TRANSPORT_TCP ) {
        contents_dns_orig = new Contents_DNS(conn, true, interp);
        contents_dns_resp = new Contents_DNS(conn, false, interp);
        AddSupportAnalyzer(contents_dns_orig);
        AddSupportAnalyzer(contents_dns_resp);
    }
    else {
        ADD_ANALYZER_TIMER(&DNS_Analyzer::ExpireTimer, run_state::network_time + zeek::detail::dns_session_timeout,
                           true, zeek::detail::TIMER_DNS_EXPIRE);
    }
}

DNS_Analyzer::~DNS_Analyzer() { delete interp; }

void DNS_Analyzer::Done() {
    analyzer::tcp::TCP_ApplicationAnalyzer::Done();

    if ( Conn()->ConnTransport() == TRANSPORT_UDP )
        Event(udp_session_done);
    else
        interp->Timeout();
}

void DNS_Analyzer::DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq, const IP_Hdr* ip, int caplen) {
    analyzer::tcp::TCP_ApplicationAnalyzer::DeliverPacket(len, data, orig, seq, ip, caplen);
    interp->ParseMessage(data, len, orig ? 1 : 0);
}

void DNS_Analyzer::ConnectionClosed(analyzer::tcp::TCP_Endpoint* endpoint, analyzer::tcp::TCP_Endpoint* peer,
                                    bool gen_event) {
    analyzer::tcp::TCP_ApplicationAnalyzer::ConnectionClosed(endpoint, peer, gen_event);

    assert(contents_dns_orig && contents_dns_resp);
    contents_dns_orig->Flush();
    contents_dns_resp->Flush();
}

void DNS_Analyzer::ExpireTimer(double t) {
    // The - 1.0 in the following is to allow 1 second for the
    // common case of a single request followed by a single reply,
    // so we don't needlessly set the timer twice in that case.
    if ( t - Conn()->LastTime() >= zeek::detail::dns_session_timeout - 1.0 || run_state::terminating ) {
        Event(connection_timeout);
        session_mgr->Remove(Conn());
    }
    else
        ADD_ANALYZER_TIMER(&DNS_Analyzer::ExpireTimer, t + zeek::detail::dns_session_timeout, true,
                           zeek::detail::TIMER_DNS_EXPIRE);
}

} // namespace zeek::analyzer::dns
