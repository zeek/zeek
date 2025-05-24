# @TEST-DOC: Calling listen_websocket() with badly configured WebSocketTLSOptions.
#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr


event zeek_init()
	{
	local tls_options_no_key = Cluster::WebSocketTLSOptions(
		$cert_file="../localhost.crt",
	);

	local tls_options_no_cert = Cluster::WebSocketTLSOptions(
		$key_file="../localhost.key",
	);

	assert ! Cluster::listen_websocket([$listen_addr=127.0.0.1, $listen_port=1234/tcp, $tls_options=tls_options_no_key]);
	assert ! Cluster::listen_websocket([$listen_addr=127.0.0.1, $listen_port=1234/tcp, $tls_options=tls_options_no_cert]);
	}
