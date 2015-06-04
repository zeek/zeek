# @TEST-EXEC: bro -r $TRACES/smtp.trace %INPUT
# @TEST-EXEC: btest-diff pacf.log
# @TEST-EXEC: btest-diff openflow.log

@load base/frameworks/pacf

global of_controller: OpenFlow::Controller;

event bro_init()
	{
	of_controller = OpenFlow::log_new(42);
	local pacf_of = Pacf::create_openflow(of_controller);
	Pacf::activate(pacf_of, 0);
	}

event connection_established(c: connection)
	{
	Pacf::quarantine_host(c$id$orig_h, 8.8.8.8, 192.169.18.1, 10hrs);
	}
