# @TEST-DOC: Allow listening with the same tls_options on the same port, but fail for disagreeing tls_options.
#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER='sed -E "s/127.0.0.1:[0-9]+/127.0.0.1:<port>/g" | $SCRIPTS/diff-remove-abspath' btest-diff .stderr
#
# @TEST-PORT: WEBSOCKET_PORT
# @TEST-PORT: WEBSOCKET_SECURE_PORT

event zeek_init()
	{
	local tls_options = Cluster::WebSocketTLSOptions(
		$cert_file="../localhost.crt",
		$key_file="../localhost.key",
	);

	local tls_options_2 = Cluster::WebSocketTLSOptions(
		$cert_file="../localhost.crt",
		$key_file="../localhost.key",
	);
	local ws_port = to_port(getenv("WEBSOCKET_PORT"));
	local wss_port = to_port(getenv("WEBSOCKET_SECURE_PORT"));

	local ws_opts = Cluster::WebSocketServerOptions($listen_addr=127.0.0.1, $listen_port=ws_port);
	local ws_opts_x = copy(ws_opts);
	ws_opts_x$tls_options = tls_options;

	local ws_opts_wss_port = Cluster::WebSocketServerOptions($listen_addr=127.0.0.1, $listen_port=wss_port);

	local ws_tls_opts = Cluster::WebSocketServerOptions(
		$listen_addr=127.0.0.1,
		$listen_port=wss_port,
		$tls_options=tls_options,
	);
	# Same as ws_tls_opts
	local ws_tls_opts_copy = Cluster::WebSocketServerOptions(
		$listen_addr=127.0.0.1,
		$listen_port=wss_port,
		$tls_options=tls_options_2,
	);

	assert Cluster::listen_websocket(ws_opts);
	assert Cluster::listen_websocket(ws_opts);
	assert ! Cluster::listen_websocket(ws_opts_x);
	assert Cluster::listen_websocket(ws_tls_opts);
	assert Cluster::listen_websocket(ws_tls_opts);
	assert Cluster::listen_websocket(ws_tls_opts_copy);
	assert ! Cluster::listen_websocket(ws_opts_wss_port);

	# Using a different max_event_queue_size fails, but using the default should work.
	local ws_opts_qs = copy(ws_opts);
	ws_opts_qs$max_event_queue_size = 42;
	assert ! Cluster::listen_websocket(ws_opts_qs);
	ws_opts_qs$max_event_queue_size = Cluster::default_websocket_max_event_queue_size;
	assert Cluster::listen_websocket(ws_opts_qs);

	terminate();
	}
