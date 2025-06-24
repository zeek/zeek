// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/analyzer/protocol/ftp/FTP.h"

#include <cstdlib>

#include "zeek/Base64.h"
#include "zeek/RuleMatcher.h"
#include "zeek/ZeekString.h"
#include "zeek/analyzer/Manager.h"
#include "zeek/analyzer/protocol/ftp/events.bif.h"
#include "zeek/analyzer/protocol/login/NVT.h"

namespace zeek::analyzer::ftp {

FTP_Analyzer::FTP_Analyzer(Connection* conn) : analyzer::tcp::TCP_ApplicationAnalyzer("FTP", conn) {
    nvt_orig = new analyzer::login::NVT_Analyzer(conn, true);
    nvt_orig->SetIsNULSensitive(true);
    nvt_orig->SetCRLFAsEOL(tcp::LF_as_EOL);

    nvt_resp = new analyzer::login::NVT_Analyzer(conn, false);
    nvt_resp->SetIsNULSensitive(true);
    nvt_resp->SetCRLFAsEOL(tcp::LF_as_EOL);

    nvt_resp->SetPeer(nvt_orig);
    nvt_orig->SetPeer(nvt_resp);

    AddSupportAnalyzer(nvt_orig);
    AddSupportAnalyzer(nvt_resp);
}

void FTP_Analyzer::Done() {
    analyzer::tcp::TCP_ApplicationAnalyzer::Done();

    if ( TCP() ) {
        if ( nvt_orig->HasPartialLine() && (TCP()->OrigState() == analyzer::tcp::TCP_ENDPOINT_CLOSED ||
                                            TCP()->OrigPrevState() == analyzer::tcp::TCP_ENDPOINT_CLOSED) )
            // ### should include the partial text
            Weird("partial_ftp_request");
    }
}

static uint32_t get_reply_code(int len, const char* line) {
    if ( len >= 3 && isdigit(line[0]) && isdigit(line[1]) && isdigit(line[2]) )
        return (line[0] - '0') * 100 + (line[1] - '0') * 10 + (line[2] - '0');
    else
        return 0;
}

// The minimal length of an FTP command is 3 characters (PWD, MKD,
// RMD, ...) and should only contain printable ascii.
static bool is_ftp_cmd(int len, const char* s) {
    if ( len < 3 )
        return false;

    for ( int i = 0; i < len; i++ )
        if ( ! isprint(s[i]) || isspace(s[i]) )
            return false;

    return true;
}

void FTP_Analyzer::DeliverStream(int length, const u_char* data, bool orig) {
    analyzer::tcp::TCP_ApplicationAnalyzer::DeliverStream(length, data, orig);

    if ( tls_active ) {
        ForwardStream(length, data, orig);
        return;
    }

    if ( (orig && ! ftp_request) || (! orig && ! ftp_reply) )
        return;

    // const char* orig_line = line;
    const char* line = (const char*)data;
    const char* end_of_line = line + length;

    if ( length == 0 )
        // Could emit "ftp empty request/reply" weird, but maybe not worth it.
        return;

    Args vl;

    EventHandlerPtr f;
    if ( orig ) {
        int cmd_len;
        const char* cmd;
        StringVal* cmd_str;

        line = util::skip_whitespace(line, end_of_line);
        util::get_word(end_of_line - line, line, cmd_len, cmd);
        line = util::skip_whitespace(line + cmd_len, end_of_line);

        if ( ! is_ftp_cmd(cmd_len, cmd) ) {
            if ( AnalyzerConfirmed() )
                Weird("FTP_invalid_command");

            // Ignore the whole line.
            return;
        }
        else if ( BifConst::FTP::max_command_length > 0 &&
                  static_cast<zeek_uint_t>(cmd_len) > BifConst::FTP::max_command_length ) {
            // If the FTP command is unusually long, log a weird if the analyzer
            // has previously been confirmed, but otherwise just ignore the whole
            // line and move on to the next.
            if ( AnalyzerConfirmed() )
                Weird("FTP_max_command_length_exceeded", util::fmt("%d", cmd_len));

            return;
        }
        else
            cmd_str = (new StringVal(cmd_len, cmd))->ToUpper();

        vl = {
            ConnVal(),
            IntrusivePtr{AdoptRef{}, cmd_str},
            make_intrusive<StringVal>(end_of_line - line, line),
        };

        f = ftp_request;
        AnalyzerConfirmation();

        if ( strncmp((const char*)cmd_str->Bytes(), "AUTH", cmd_len) == 0 )
            auth_requested = std::string(line, end_of_line - line);

        if ( detail::rule_matcher )
            Conn()->Match(zeek::detail::Rule::FTP, (const u_char*)cmd, end_of_line - cmd, true, true, true, true);
    }
    else {
        uint32_t reply_code = get_reply_code(length, line);

        int cont_resp;

        if ( pending_reply ) {
            if ( reply_code == pending_reply && length > 3 && line[3] == ' ' ) {
                // This is the end of the reply.
                line = util::skip_whitespace(line + 3, end_of_line);
                pending_reply = 0;
                cont_resp = 0;
            }
            else {
                cont_resp = 1;  // not the end
                reply_code = 0; // flag as intermediary
            }
        }
        else { // a new reply
            cont_resp = 0;

            if ( reply_code == 0 ) {
                AnalyzerViolation("non-numeric reply code", (const char*)data, length);
                return;
            }
            else if ( reply_code < 100 ) {
                AnalyzerViolation("invalid reply code", (const char*)data, length);
                return;
            }
            else if ( length > 3 && line[3] == '-' ) { // a continued reply
                pending_reply = reply_code;
                line = util::skip_whitespace(line + 4, end_of_line);
                cont_resp = 1;
            }
            else if ( length > 3 && line[3] != ' ' ) {
                // This is a proper reply code, but there's no space after
                // the reply code even though the line is long enough.
                AnalyzerViolation("invalid reply line", (const char*)data, length);
                return;
            }
            else { // a self-contained reply
                line += 3;

                if ( line < end_of_line )
                    line = util::skip_whitespace(line, end_of_line);
                else
                    line = end_of_line;
            }
        }

        if ( reply_code == 234 && auth_requested.size() > 0 && auth_requested == "TLS" ) {
            EnqueueConnEvent(ftp_starttls, ConnVal());
            Analyzer* ssl = analyzer_mgr->InstantiateAnalyzer("SSL", Conn());
            if ( ssl ) {
                AddChildAnalyzer(ssl);
                RemoveSupportAnalyzer(nvt_orig);
                RemoveSupportAnalyzer(nvt_resp);
                tls_active = true;
            }
        }

        if ( reply_code == 334 && auth_requested.size() > 0 && auth_requested == "GSSAPI" ) {
            // Server wants to proceed with an ADAT exchange and we
            // know how to analyze the GSI mechanism, so attach analyzer
            // to look for that.
            Analyzer* ssl = analyzer_mgr->InstantiateAnalyzer("SSL", Conn());
            if ( ssl ) {
                ssl->AddSupportAnalyzer(new FTP_ADAT_Analyzer(Conn(), true));
                ssl->AddSupportAnalyzer(new FTP_ADAT_Analyzer(Conn(), false));
                AddChildAnalyzer(ssl);
            }
        }

        vl = {ConnVal(), val_mgr->Count(reply_code), make_intrusive<StringVal>(end_of_line - line, line),
              val_mgr->Bool(cont_resp)};

        f = ftp_reply;
    }

    EnqueueConnEvent(f, std::move(vl));

    if ( ! tls_active )
        ForwardStream(length, data, orig);
}

void FTP_ADAT_Analyzer::DeliverStream(int len, const u_char* data, bool orig) {
    // Don't know how to parse anything but the ADAT exchanges of GSI GSSAPI,
    // which is basically just TLS/SSL.
    if ( ! Parent()->IsAnalyzer("SSL") ) {
        Parent()->Remove();
        return;
    }

    bool done = false;
    const char* line = (const char*)data;
    const char* end_of_line = line + len;

    String* decoded_adat = nullptr;

    if ( orig ) {
        int cmd_len;
        const char* cmd;
        line = util::skip_whitespace(line, end_of_line);
        util::get_word(len, line, cmd_len, cmd);

        if ( strncmp(cmd, "ADAT", cmd_len) == 0 ) {
            line = util::skip_whitespace(line + cmd_len, end_of_line);
            StringVal encoded(end_of_line - line, line);
            decoded_adat = detail::decode_base64(encoded.AsString(), nullptr, Conn());

            if ( first_token ) {
                // RFC 2743 section 3.1 specifies a framing format for tokens
                // that includes an identifier for the mechanism type.  The
                // framing is supposed to be required for the initial context
                // token, but GSI doesn't do that and starts right in on a
                // TLS/SSL handshake, so look for that to identify it.
                const u_char* msg = nullptr;
                int msg_len = 0;

                if ( decoded_adat ) {
                    msg = decoded_adat->Bytes();
                    msg_len = decoded_adat->Len();
                }
                else
                    Weird("ftp_adat_bad_first_token_encoding");

                // Just check that it looks like a viable TLS/SSL handshake
                // record from the first byte (content type of 0x16) and
                // that the fourth and fifth bytes indicating the length of
                // the record match the length of the decoded data.
                if ( msg_len < 5 || msg[0] != 0x16 || msg_len - 5 != ntohs(*((uint16_t*)(msg + 3))) ) {
                    // Doesn't look like TLS/SSL, so done analyzing.
                    done = true;
                    delete decoded_adat;
                    decoded_adat = nullptr;
                }
            }

            first_token = false;
        }

        else if ( strncmp(cmd, "AUTH", cmd_len) == 0 )
            // Security state will be reset by a reissued AUTH.
            done = true;
    }

    else {
        uint32_t reply_code = get_reply_code(len, line);

        switch ( reply_code ) {
            case 232:
            case 234:
                // Indicates security data exchange is complete, but nothing
                // more to decode in replies.
                done = true;
                break;

            case 235:
                // Security data exchange complete, but may have more to decode
                // in the reply (same format at 334 and 335).
                done = true;

                // Fall-through.

            case 334:
            case 335:
                // Security data exchange still in progress, and there could be data
                // to decode in the reply.
                line += 3;
                if ( len > 3 && line[0] == '-' )
                    line++;

                line = util::skip_whitespace(line, end_of_line);

                if ( end_of_line - line >= 5 && strncmp(line, "ADAT=", 5) == 0 ) {
                    line += 5;
                    StringVal encoded(end_of_line - line, line);
                    decoded_adat = zeek::detail::decode_base64(encoded.AsString(), nullptr, Conn());
                }

                break;

            // Server isn't going to accept named security mechanism.
            // Client has to restart back at the AUTH.
            case 421:
            case 431:
            case 500:
            case 501:
            case 503:
            case 535:

            // If the server is sending protected replies, the security
            // data exchange must have already succeeded.  It does have
            // encoded data in the reply, but 632 and 633 are also encrypted.
            case 631:
            case 632:
            case 633: done = true; break;

            default: break;
        }
    }

    if ( decoded_adat ) {
        ForwardStream(decoded_adat->Len(), decoded_adat->Bytes(), orig);
        delete decoded_adat;
    }

    if ( done )
        Parent()->Remove();
}

} // namespace zeek::analyzer::ftp
