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
			SSH_Analyzer(Connection* conn);
			virtual ~SSH_Analyzer();

			// Overriden from Analyzer.
			virtual void Done();
			virtual void DeliverStream(int len, const u_char* data, bool orig);
			virtual void Undelivered(uint64 seq, int len, bool orig);

			// Overriden from tcp::TCP_ApplicationAnalyzer.
			virtual void EndpointEOF(bool is_orig);

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
