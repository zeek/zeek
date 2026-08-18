# @TEST-DOC: Regression test for #5798. Start Zeek with a websocket listener, start a raw reader inside it, kill -9 Zeek such that the raw reader continues to exist. Start a second Zeek process with a websocket listener again.
#
# @TEST-REQUIRES: have-zeromq
# @TEST-REQUIRES: ! is-windows-ci
# @TEST-REQUIRES: which bash
#
# @TEST-GROUP: cluster-zeromq
#
# @TEST-PORT: WEBSOCKET_PORT
#
# @TEST-EXEC: RUN=1 zeek -b %INPUT &
# @TEST-EXEC: wait-for-file zeek-1.pid 30
# @TEST-EXEC: wait-for-file child.pid 30
#
# Make the parent Zeek process go, but the child process survive.
# @TEST-EXEC: kill -9 $(cat zeek-1.pid)
#
# Give the Zeek process 10 seconds to vanish.
# @TEST-EXEC: for i in {0..100}; do if kill -0 "$(cat zeek-1.pid)" >&2; then sleep 0.1; else break; fi done
#
# Check that the Zeek process is gone (kill -0 fails)
# @TEST-EXEC-FAIL: kill -0 $(cat zeek-1.pid)
#
# Check that the child bash process is still running (kill -0 succeeds)
# @TEST-EXEC: kill -0 $(cat child.pid)
#
# Start another instance of Zeek that will just try to open the listening
# socket and terminate directly. Don't expect any errors.
# @TEST-EXEC: RUN=2 zeek -b %INPUT
# @TEST-EXEC: test -f zeek-2.pid
#
# Check that the child bash process spawned from the raw reader
# is still running, then clean it up using SIGKILL.
# @TEST-EXEC: kill -0 $(cat child.pid)
# @TEST-EXEC: kill -9 $(cat child.pid)

@load base/frameworks/input

redef exit_only_after_terminate = T;

type Line: record { s: string; };

event line(desc: Input::EventDescription, tpe: Input::Event, s: string) { }

event do_terminate()
	{
	terminate();
	}

event zeek_init()
	{
	local r = Cluster::listen_websocket([$listen_addr=127.0.0.1, $listen_port=getenv("WEBSOCKET_PORT") as port]);
	if ( ! r )
		Reporter::fatal(fmt("failed to listen on port %s", getenv("WEBSOCKET_PORT")));

	local pidfile = fmt("zeek-%s.pid", getenv("RUN"));
	system(fmt("echo %s > %s", getpid(), pidfile));

	if ( getenv("RUN") == "1" )
		{
		# Loop 30 seconds at most.
		Input::add_event([$name="child", $source="bash -c 'echo $$ > child.pid; for i in {0..300}; do echo $$; sleep 0.1; done' |",
				  $reader=Input::READER_RAW, $mode=Input::STREAM,
				  $fields=Line, $ev=line, $want_record=F]);
		}
	else if ( getenv("RUN") == "2" )
		{
		schedule 100msec { do_terminate() };
		}
	}
