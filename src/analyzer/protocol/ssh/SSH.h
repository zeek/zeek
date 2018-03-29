// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ANALYZER_PROTOCOL_SSH_SSH_H
#define ANALYZER_PROTOCOL_SSH_SSH_H

#include "events.bif.h"

#include "analyzer/protocol/tcp/TCP.h"
#include "ssh_pac.h"

namespace analyzer {
	namespace SSH {
		class SSH_Analyzer : public tcp::TCP_ApplicationAnalyzer {

		public:
			explicit SSH_Analyzer(Connection* conn);
			~SSH_Analyzer() override;

			// Overriden from Analyzer.
			void Done() override;
			void DeliverStream(int len, const u_char* data, bool orig) override;
			void Undelivered(uint64 seq, int len, bool orig) override;

			// Overriden from tcp::TCP_ApplicationAnalyzer.
			void EndpointEOF(bool is_orig) override;

			static analyzer::Analyzer* Instantiate(Connection* conn)
				{ return new SSH_Analyzer(conn); }

		protected:
			binpac::SSH::SSH_Conn* interp;

			void ProcessEncrypted(int len, bool orig);

			bool had_gap;

			// Packet analysis stuff
			bool auth_decision_made;
			bool skipped_banner;

			int service_accept_size;
			int userauth_failure_size;

			};

		}
	}
#endif
