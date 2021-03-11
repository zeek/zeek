#pragma once

#include "zeek/analyzer/protocol/tcp/TCP_Endpoint.h"

namespace zeek::analyzer::tcp {

// A TCPStateStats object tracks the distribution of TCP states for
// the currently active connections.
class TCPStateStats {
public:
	TCPStateStats();
	~TCPStateStats() = default;

	void ChangeState(EndpointState o_prev, EndpointState o_now,
				EndpointState r_prev, EndpointState r_now);
	void FlipState(EndpointState orig, EndpointState resp);

	void StateEntered (EndpointState o_state, EndpointState r_state)
		{ ++state_cnt[o_state][r_state]; }
	void StateLeft (EndpointState o_state, EndpointState r_state)
		{ --state_cnt[o_state][r_state]; }

	unsigned int Cnt(EndpointState state) const
		{ return Cnt(state, state); }
	unsigned int Cnt(EndpointState state1, EndpointState state2) const
		{ return state_cnt[state1][state2]; }

	unsigned int NumStateEstablished() const
		{ return Cnt(TCP_ENDPOINT_ESTABLISHED); }
	unsigned int NumStateHalfClose() const
		{ // corresponds to S2,S3
		return Cnt(TCP_ENDPOINT_ESTABLISHED, TCP_ENDPOINT_CLOSED) +
			Cnt(TCP_ENDPOINT_CLOSED, TCP_ENDPOINT_ESTABLISHED);
		}
	unsigned int NumStateHalfRst() const
		{
		return Cnt(TCP_ENDPOINT_ESTABLISHED, TCP_ENDPOINT_RESET) +
			Cnt(TCP_ENDPOINT_RESET, TCP_ENDPOINT_ESTABLISHED);
		}
	unsigned int NumStateClosed() const
		{ return Cnt(TCP_ENDPOINT_CLOSED); }
	unsigned int NumStateRequest() const
		{
		assert(Cnt(TCP_ENDPOINT_INACTIVE, TCP_ENDPOINT_SYN_SENT)==0);
		return Cnt(TCP_ENDPOINT_SYN_SENT, TCP_ENDPOINT_INACTIVE);
		}
	unsigned int NumStateSuccRequest() const
		{
		return Cnt(TCP_ENDPOINT_SYN_SENT, TCP_ENDPOINT_SYN_ACK_SENT) +
			Cnt(TCP_ENDPOINT_SYN_ACK_SENT, TCP_ENDPOINT_SYN_SENT);
		}
	unsigned int NumStateRstRequest() const
		{
		return Cnt(TCP_ENDPOINT_SYN_SENT, TCP_ENDPOINT_RESET) +
			Cnt(TCP_ENDPOINT_RESET, TCP_ENDPOINT_SYN_SENT);
		}
	unsigned int NumStateInactive() const
		{ return Cnt(TCP_ENDPOINT_INACTIVE); }
	unsigned int NumStatePartial() const;

	void PrintStats(File* file, const char* prefix);

private:
	unsigned int state_cnt[TCP_ENDPOINT_RESET+1][TCP_ENDPOINT_RESET+1];
};

} // namespace zeek::analyzer::tcp
