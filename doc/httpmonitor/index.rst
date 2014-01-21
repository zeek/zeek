
.. _http-monitor:

================================
Monitoring HTTP Traffic with Bro
================================

Bro can be used to log the entire HTTP traffic from your network to the http.log file.
This file can then be used for analysis and auditing purposes.

In the sections below we briefly explain the structure of the http.log file. Then, we
show you how to perform basic HTTP traffic monitoring and analysis tasks with Bro. Some 
of these ideas and techniques can later be applied to monitor different protocols in a
similar way.

----------------------------
Introduction to the HTTP log
----------------------------

The http.log file contains a summary of all HTTP requests and responses sent over a Bro-monitored
network. Here are the first few columns of 
``http.log``::

    # ts          uid          orig_h        orig_p  resp_h         resp_p
    1311627961.8  HSH4uV8KVJg  192.168.1.100 52303   192.150.187.43 80

Every single line in this log starts with a timestamp, a unique connection identifier (UID), and a 
connection 4-tuple (originator host/port and responder host/port).  The UID can be used to
identify all logged activity (possibly across multiple log files) associated
with a given connection 4-tuple over its lifetime.

The remaining columns detail the activity that's occurring.  For example, the columns on the line below 
(shortened for brevity) show a request to the root of Bro website::

    # method   host         uri  referrer  user_agent
    GET        bro.org  /    -         <...>Chrome/12.0.742.122<...>

Network administrators and security engineers, for instance, can use the information in this log to understand
the HTTP activity on the network and troubleshoot network problems or search for anomalous activities. At this
point, we would like to stress out the fact that there is no just one right way to perform analysis; it will
depend on the expertise of the person doing the analysis and the specific details of the task to accomplish.

For more information about how to handle the HTTP protocol in Bro, including a complete list 
of the fields available in http.log, go to Bro's
:doc:`HTTP script reference </scripts/base/protocols/http/main.bro>`.

------------------------
Detecting a Proxy Server
------------------------

A proxy server is a device on your network configured to request a service on behalf of a third system; one of the
most common examples is a Web proxy server. A client without Internet access connects to the proxy and requests
a Web page; the proxy then sends the request to the actual Web server, receives the response and passes it to the original
client.

Proxies were conceived to help manage a network and provide better encapsulation. By themselves, proxies are not a security
threat, but a misconfigured or unauthorized proxy can allow others, either inside or outside the network, to access any
Web site and even conduct malicious activities anonymously using the network resources.

What Proxy Server traffic looks like
-------------------------------------

In general, when a client starts talking with a proxy server, the traffic consists of two parts: (i) a GET request, and 
(ii) an HTTP/ reply::

    Request: GET http://www.bro.org/ HTTP/1.1
    Reply:   HTTP/1.0 200 OK

This will differ from traffic between a client and a normal Web server because GET requests should not include "http" on
the string. So we can use this to identify a proxy server.

We can write a basic script in Bro to handle the http_reply event and detect a reply for a ``GET http://`` request.

  .. code:: bro

	event http_reply(c: connection, version: string, code: count, reason: string)
		{
			if ( /^[hH][tT][tT][pP]:/ in c$http$uri && c$http$status_code == 200 )
		                {			
				print fmt("A local server is acting as an open proxy: ", c$id$resp_h);
		                }
		}

Basically, the script is checking for a "200 OK" status code on a reply for a request that includes "http:". In reality, the HTTP
protocol defines several success status codes other than 200, so we will extend our basic script to also consider the additional codes.

  .. code:: bro

	export {

		global success_status_codes: set[count] = {
		        200,
		        201,
		        202,
		        203,
		        204,
		        205,
		        206,
		        207,
		        208,
		        226,
			304
		        };

	}

	event http_reply(c: connection, version: string, code: count, reason: string)
		{
			if ( /^[hH][tT][tT][pP]:/ in c$http$uri && c$http$status_code in success_status_codes )
		                {			
				print fmt("A local server is acting as an open proxy: ", c$id$resp_h);
		                }
		}

Next, we will make sure that the responding proxy is part of our local network.

  .. code:: bro

	export {

		global success_status_codes: set[count] = {
		        200,
		        201,
		        202,
		        203,
		        204,
		        205,
		        206,
		        207,
		        208,
		        226,
			304
		        };

	}

	event http_reply(c: connection, version: string, code: count, reason: string)
		{
			if ( Site::is_local_addr(c$id$resp_h) && /^[hH][tT][tT][pP]:/ in c$http$uri && c$http$status_code in success_status_codes )
		                {			
				print fmt("A local server is acting as an open proxy: ", c$id$resp_h);
		                }
		}

Finally, our goal should be to generate an alert when a proxy has been detected instead of printing a message on the console output.
For that, we will tag the traffic accordingly and define a new ``Open_Proxy`` ``Notice`` type to alert of all tagged communications. Once a
notification has been fired, we will further suppress it for one day. Below is the complete script.

  .. code:: bro

	@load base/frameworks/notice

	module HTTP;

	export {

		redef enum HTTP::Tags += {
		        OPEN_PROXY_TAG
		};
		redef enum Notice::Type += {
		       Open_Proxy
		};

		global success_status_codes: set[count] = {
		        200,
		        201,
		        202,
		        203,
		        204,
		        205,
		        206,
		        207,
		        208,
		        226,
			304
		        };

	}

	redef Notice::emailed_types += {
		Open_Proxy,
	};

	function open_proxy_only(rec: HTTP::Info) : bool
		{
		# Only write out connections with the OPEN_PROXY_TAG.
		return OPEN_PROXY_TAG in rec$tags;
		}

	event http_reply(c: connection, version: string, code: count, reason: string)
		{
		        # make sure responding host is local
		        #if ( Site::is_local_addr(c$id$resp_h) && /^[hH][tT][tT][pP]:/ in c$http$uri && c$http$status_code in success_status_codes )
		                {			
		                add c$http$tags[OPEN_PROXY_TAG];
				local ident = cat(c$id$resp_h);
		                if ( c$http?$host ) #check if the optional host field exists in http
					{
					print fmt("Originator host: %s", c$id$orig_h);
		                        NOTICE([$note=HTTP::Open_Proxy,
		                                $msg=cat("A local server is acting as an open proxy: ", c$id$resp_h),
		                                $conn=c, $identifier=cat(ident, c$id$resp_h),
		                                $suppress_for=1day]);
					}
		                }
		}

	event bro_init()
		{
		#Creating a new filter for all open proxy logs.
		local filter: Log::Filter = [$name="open_proxy", $path="open_proxy", $pred=open_proxy_only];
		Log::add_filter(HTTP::LOG, filter);
		}

----------------
Inspecting Files
----------------

Files are often transmitted on regular HTTP conversations between a client and a server. Most of the time these files are harmless, 
just images and some other multimedia content, but there are also types of files, specially executable files, that can damage
your system. We can instruct Bro to create a copy of all executable files that it sees for later analysis using the
:ref:`File Analysis Framework <file-analysis-framework>`
(introduced with Bro 2.2) as shown in the following script.

    .. code:: bro

        global ext_map: table[string] of string = {
            ["application/x-dosexec"] = "exe",
        } &default ="";

        event file_new(f: fa_file)
            {
            local ext = "";

            if ( f?$mime_type )
                ext = ext_map[f$mime_type];

            local fname = fmt("%s-%s.%s", f$source, f$id, ext);
            Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
            }

Bro will extract all files from the traffic and write them on a new ``extract_files/`` subdirectory and change the file name with the right 
suffix (extension) based on the content of the ext_map table. So, if you want to do the same for other extracted files besides executables 
you just need to add those types to the ``ext_map`` table like this.

    .. code:: bro

        global ext_map: table[string] of string = {
            ["application/x-dosexec"] = "exe",
            ["text/plain"] = "txt",
            ["image/jpeg"] = "jpg",
            ["image/png"] = "png",
            ["text/html"] = "html",
        } &default ="";

Bro will now write the appropriate suffix for text, JPEG, PNG, and HTML files stored in the ``extract_files/`` subdirectory.
