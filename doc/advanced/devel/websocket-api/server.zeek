global hello: event(c : count);

global c = 0;

event tick()
	{
	Cluster::publish("zeek.bridge.test", hello, ++c);
	schedule 1.0sec { tick() };
	}

event zeek_init()
	{
	Cluster::listen_websocket([$listen_addr=127.0.0.1, $listen_port=8000/tcp]);
	event tick();
	}
