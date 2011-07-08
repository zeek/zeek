##! This script is the wrapper script for HTTP analysis.
##! :Author: Seth Hall <seth@icir.org> - Inspired by the work of many others.

@load protocols/http/base/main

#@load protocols/http/detect-MHR
#@load protocols/http/headers

# Disabling web app detection for now.  It's too intense and will probably
# be moved out of the core http protocol support later.
#@load http/detect-webapps