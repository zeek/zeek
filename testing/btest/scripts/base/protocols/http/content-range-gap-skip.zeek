# @TEST-EXEC: zeek -r $TRACES/http/content-range-gap-skip.trace %INPUT

# In this trace, we should be able to determine that a gap lies
# entirely within the body of an entity that specifies Content-Range,
# and so further deliveries after the gap can still be made.

global got_gap = F;
global got_data_after_gap = F;

event http_entity_data(c: connection, is_orig: bool, length: count,
                       data: string)
	{
	if ( got_gap )
		got_data_after_gap = T;
	}

event content_gap(c: connection, is_orig: bool, seq: count, length: count)
	{
	got_gap = T;
	}

event zeek_done()
	{
	if ( ! got_data_after_gap )
		exit(1);
	}
