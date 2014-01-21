
.. _mime-stats:

====================
MIME Type Statistics
====================

Files are constantly transmitted over HTTP on regular networks. These
files belong to a specific category (i.e., executable, text, image,
etc.) identified by a `Multipurpose Internet Mail Extension (MIME)
<http://en.wikipedia.org/wiki/MIME>`_. Although MIME was originally
developed to identify the type of non-text attachments on email, it is
also used by Web browser to identify the type of files transmitted and
present them accordingly.

In this tutorial, we will show how to use the Sumstats Framework to
collect some statistics information based on MIME types, specifically
the total number of occurrences, size in bytes, and number of unique
hosts transmitting files over HTTP per each type. For instructions about
extracting and creating a local copy of these files, visit :ref:`this
<http-monitor>` tutorial instead.

------------------------------------------------
MIME Statistics with Sumstats
------------------------------------------------

When working with the :ref:`Summary Statistics Framework
<sumstats-framework>`, you need to define three different pieces: (i)
Observations, where the event is observed and fed into the framework.
(ii) Reducers, where observations are collected and measured. (iii)
Sumstats, where the main functionality is implemented.

So, we start by defining our observation along with a record to store
all statistics values and an observation interval. We are conducting our
observation on the :bro:see:`HTTP::log_http` event and we are interested
in the MIME type, size of the file ("response_body_len") and the
originator host ("orig_h"). We use the MIME type as our key and create
observers for the other two values.

  .. code:: bro

	export {
	    redef enum Log::ID += { LOG };
		type Info: record {
		        ## Timestamp when the log line was finished and written.
		        ts:         time   &log;
		        ## Time interval that the log line covers.
		        ts_delta:   interval &log;
		        ## The mime type
		        mtype:        string &log;
		        ## The number of unique local hosts that fetched this mime type
		        uniq_hosts: count  &log;
		        ## The number of hits to the mime type 
		        hits:       count  &log;
		        ## The total number of bytes received by this mime type
		        bytes:      count  &log;
		};

		## The frequency of logging the stats collected by this script.
		const break_interval = 5mins &redef;
	}

	event HTTP::log_http(rec: HTTP::Info)
	{
	    if(Site::is_local_addr(rec$id$orig_h) && rec?$resp_mime_types) {
		local mime_type = rec$resp_mime_types[0];
		SumStats::observe("mime.bytes", [$str=mime_type], [$num=rec$response_body_len]);
		SumStats::observe("mime.hits",  [$str=mime_type], [$str=cat(rec$id$orig_h)]);
	    }
	}

Next, we create the reducers. The first one will accumulate file sizes
and the second one will make sure we only store a host ID once. Below is
the partial code.

  .. code:: bro

        local r1: SumStats::Reducer = [$stream="mime.bytes", $apply=set(SumStats::SUM)];
        local r2: SumStats::Reducer = [$stream="mime.hits",  $apply=set(SumStats::UNIQUE)];

In our final step, we create the SumStats where we check for the
observation interval and once it expires, we populate the record
(defined above) with all the relevant data and write it to a log.

  .. code:: bro

        SumStats::create([$name="mime-metrics",
                          $epoch=break_interval,
                          $reducers=set(r1, r2),
                          $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                                {
                                local l: Info;
                                l$ts         = network_time();
                                l$ts_delta   = break_interval;
                                l$mtype      = key$str;
                                l$bytes      = double_to_count(floor(result["mime.bytes"]$sum));
                                l$hits       = result["mime.hits"]$num;
                                l$uniq_hosts = result["mime.hits"]$unique;
                                Log::write(LOG, l);
                                }]);

Putting everything together we end up with the following final code for
our script.

  .. code:: bro

	@load base/frameworks/sumstats

	module MimeMetrics;

	export {
	    redef enum Log::ID += { LOG };
		type Info: record {
		        ## Timestamp when the log line was finished and written.
		        ts:         time   &log;
		        ## Time interval that the log line covers.
		        ts_delta:   interval &log;
		        ## The mime type
		        mtype:        string &log;
		        ## The number of unique local hosts that fetched this mime type
		        uniq_hosts: count  &log;
		        ## The number of hits to the mime type 
		        hits:       count  &log;
		        ## The total number of bytes received by this mime type
		        bytes:      count  &log;
		};

		## The frequency of logging the stats collected by this script.
		const break_interval = 5mins &redef;
	}

	event bro_init() &priority=3
	{
	    Log::create_stream(MimeMetrics::LOG, [$columns=Info]);
		local r1: SumStats::Reducer = [$stream="mime.bytes", $apply=set(SumStats::SUM)];
		local r2: SumStats::Reducer = [$stream="mime.hits",  $apply=set(SumStats::UNIQUE)];
		SumStats::create([$name="mime-metrics",
		                  $epoch=break_interval,
		                  $reducers=set(r1, r2),
		                  $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
		                        {
		                        local l: Info;
		                        l$ts         = network_time();
		                        l$ts_delta   = break_interval;
		                        l$mtype      = key$str;
		                        l$bytes      = double_to_count(floor(result["mime.bytes"]$sum));
		                        l$hits       = result["mime.hits"]$num;
		                        l$uniq_hosts = result["mime.hits"]$unique;
		                        Log::write(LOG, l);
		                        }]);
	}

	event HTTP::log_http(rec: HTTP::Info)
	{
	    if(Site::is_local_addr(rec$id$orig_h) && rec?$resp_mime_types) {
		local mime_type = rec$resp_mime_types[0];
		SumStats::observe("mime.bytes", [$str=mime_type], [$num=rec$response_body_len]);
		SumStats::observe("mime.hits",  [$str=mime_type], [$str=cat(rec$id$orig_h)]);
	    }
	}

