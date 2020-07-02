// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "events.bif.h"

#include "analyzer/protocol/tcp/TCP.h"
#include "ssh_pac.h"

namespace analyzer {
	namespace SSH {
		class SSH_Analyzer final : public tcp::TCP_ApplicationAnalyzer {

		public:
			explicit SSH_Analyzer(Connection* conn);
			~SSH_Analyzer() override;

			// Overriden from Analyzer.
			void Done() override;
			void DeliverStream(int len, const u_char* data, bool orig) override;
			void Undelivered(uint64_t seq, int len, bool orig) override;

			// Overriden from tcp::TCP_ApplicationAnalyzer.
			void EndpointEOF(bool is_orig) override;

			static zeek::analyzer::Analyzer* Instantiate(Connection* conn)
				{ return new SSH_Analyzer(conn); }

		protected:
			binpac::SSH::SSH_Conn* interp;

			void ProcessEncrypted(int len, bool orig);
			void ProcessEncryptedSegment(int len, bool orig);

			bool had_gap;

			// Packet analysis stuff
			bool auth_decision_made;
			bool skipped_banner;
			bool saw_encrypted_client_data;

			int service_accept_size;
			int userauth_failure_size;

		};
	}
}
