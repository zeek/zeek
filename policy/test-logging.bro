module SSH;

@load logging

# Create a new ID for our log stream
redef enum Logging::ID += { SSH };

# Define a record with all the columns the log file can have.
# (I'm using a subset of fields from ssh-ext for demonstration.)
type Log: record {
    t: time;
    id: conn_id; # Will be rolled out into individual columns.
    status: string &optional;
    country: string &default="unknown";
};

event bro_init()
{
	# Create the stream.
	Logging::create([$id=SSH, $columns=Log]);

	# Add a default filter that simply logs everything to "ssh.log" using the default writer.
	#Logging::add_filter(SSH, [$name="default", $path="ssh"]);
}

# Log something.
Logging::log(SSH, [$t=network_time(), $status="ok"]);
