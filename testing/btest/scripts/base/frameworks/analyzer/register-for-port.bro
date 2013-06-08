#
# @TEST-EXEC: bro -r ${TRACES}/ssh-on-port-80.trace %INPUT dpd_buffer_size=0;
# @TEST-EXEC: cat conn.log | bro-cut service | grep -q ssh
#
# @TEST-EXEC: bro -r ${TRACES}/ssh-on-port-80.trace dpd_buffer_size=0;
# @TEST-EXEC: cat conn.log | bro-cut service | grep -vq ssh

event bro_init()
	{
	Analyzer::register_for_port(Analyzer::ANALYZER_SSH, 80/tcp);
	}


