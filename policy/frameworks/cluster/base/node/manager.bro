##! This is the core Bro script support for the notion of a cluster manager.
##!
##! The manager is passive (the workers connect to us), and once connected
##! the manager registers for the events on the workers that are needed
##! to get the desired data from the workers.

@load frameworks/notice

##! This is where the cluster manager sets it's specific settings for other
##! frameworks and in the core.

## Set the mail script to be the default script for the cluster deployment.
redef Notice::mail_script = "mail-alarm";

## Set the template value that the mail script will use to send email.  The
## default mail-alarm script will replace the value.
redef Notice::mail_dest = "_broctl_default_";

## Set the port that the manager is supposed to listen on.
redef Communication::listen_port_clear = Cluster::nodes[Cluster::node]$p;

## Turn off remote logging since this is the manager and should only log here.
redef Log::enable_remote_logging = F;

## Make the logging framework's default log rotation 1 hour.
redef Log::default_rotation_interval = 1hr;

## Use the cluster's archive logging script.
redef Log::default_rotation_postprocessor = "archive-log";

## The cluster manager does not capture packets.
redef interfaces = "";

## Set the name for the manager.
redef peer_description = Cluster::nodes[Cluster::node]$tag;

## We're processing essentially *only* remote events.
redef max_remote_events_processed = 10000;

module Cluster;

# Reraise remote notices locally.
event Notice::notice(n: Notice::Info)
	{
	if ( is_remote_event() )
		#if ( FilterDuplicates::is_new(n) )
		NOTICE(n);
	}