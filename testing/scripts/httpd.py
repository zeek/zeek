#! /usr/bin/env python

import BaseHTTPServer

class MyRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write("It works!")

    def version_string(self):
        return "1.0"

    def date_time_string(self):
        return "July 22, 2013"


if __name__ == "__main__":
    from optparse import OptionParser
    p = OptionParser()
    p.add_option("-a", "--addr", type="string", default="localhost",
                 help=("listen on given address (numeric IP or host name), "
                       "an empty string (the default) means INADDR_ANY"))
    p.add_option("-p", "--port", type="int", default=32123,
                 help="listen on given TCP port number")
    p.add_option("-m", "--max", type="int", default=-1,
                 help="max number of requests to respond to, -1 means no max")
    options, args = p.parse_args()

    httpd = BaseHTTPServer.HTTPServer((options.addr, options.port),
                                      MyRequestHandler)
    if options.max == -1:
        httpd.serve_forever()
    else:
        served_count = 0
        while served_count != options.max:
            httpd.handle_request()
            served_count += 1
