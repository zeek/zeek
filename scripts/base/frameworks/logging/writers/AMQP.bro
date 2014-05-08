##! Log writer for sending logs to RabbitMQ.
##!

module LogAMQP;

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
    # Note that the exchange type is assumed to be topic exchange
	const queue_exchange = "broqueue" &redef;

    ## Key prefix to use on Exchange
    # messages will have the key "routing_key.type"
    const routing_key = "bro" &redef;
	
	## The batch size is the number of messages that will be queued up before
	## they are sent to rabbit.
	const max_batch_size = 1000 &redef;

	## The maximum amount of wall-clock time that is allowed to pass without
	## finishing a bulk log send.  This represents the maximum delay you
	## would like to have with your logs before they are sent to Rabbit.
	const max_batch_interval = 1min &redef;

	## The maximum byte size for a buffered JSON string to send to the bulk
	## insert API.
	const max_byte_size = 1024 * 1024 &redef;
}

