# $Id: broctl.remote.bro 6811 2009-07-06 20:41:10Z robin $

@load broctl

# Configure Time Machine.
event bro_init()
	{
	if ( BroCtl::tm_host != 0.0.0.0 )
		Remote::destinations["time-machine"] = [$host=BroCtl::tm_host, $p=BroCtl::tm_port, $connect=T, $retry=1min];
	}

