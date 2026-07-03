# The sender's test logic for drops vs disconnect on backpressure is not quite
# the same, so load the appropriate one based on the policy.
@if ( Broker::peer_overflow_policy == "disconnect" )
@load ./sender-disconnect.zeek
@else
@load ./sender-drop.zeek
@endif
