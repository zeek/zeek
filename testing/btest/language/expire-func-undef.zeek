# @TEST-EXEC: zeek -r $TRACES/rotation.trace -b %INPUT >output 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output

module segfault; 

export {

        global scan_summary:
                function(t: table[addr] of set[addr], orig: addr): interval;

        global distinct_peers: table[addr] of set[addr]
                &read_expire = 7 secs &expire_func=scan_summary &redef;

} 


event new_connection(c: connection)
{ 

	local orig = c$id$orig_h ;
	local resp = c$id$resp_h ; 


	if (orig !in distinct_peers)
		distinct_peers[orig]=set(); 
	
	if (resp !in distinct_peers[orig]) 
		add distinct_peers[orig][resp]; 

} 

event zeek_done()
{

	for (o in distinct_peers)
	{ 
		print fmt("orig: %s: peers: %s", o, distinct_peers[o]); 
	} 

} 
