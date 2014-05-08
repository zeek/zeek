##! Log writer for sending logs to an ElasticSearch server through RabbitMQ.
##!

module LogElasticSearchRabbit;

export {
	## Rabbit server.
	const server_host = "127.0.0.1" &redef;

	## Rabbit  port.
	const server_port = 5672 &redef;

	## Rabbit user.
	const server_user = "user" &redef;

	## Rabbit password.
	const server_pass = "password" &redef;

	## Exchange on Rabbit to use
	const queue_exchange = "elasticsearch" &redef;

	## Key to use on Exchange
	const routing_key = "bro" &redef;
	
	## Name of the ES index.
	const index_prefix = "bro" &redef;

	## The batch size is the number of messages that will be queued up before
	## they are sent to rabbit.
	const max_batch_size = 100 &redef;

	## The maximum amount of wall-clock time that is allowed to pass without
	## finishing a bulk log send.  This represents the maximum delay you
	## would like to have with your logs before they are sent to Rabbit.
	const max_batch_interval = 1min &redef;

	## The maximum byte size for a buffered JSON string to send to the bulk
	## insert API.
	const max_byte_size = 1024 * 1024 &redef;
}

