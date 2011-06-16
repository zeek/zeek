##! This script is the wrapper script for HTTP analysis.
##! :Author: Seth Hall <seth@icir.org> - Inspired by the work of many others.

@load http/base
@load http/detect-sqli
@load http/detect-intel
@load http/file-ident
@load http/file-hash
@load http/file-extract
@load http/software
@load http/headers

# Disabling web app detection for now.  It's too intense and will probably
# be moved out of the core http protocol support later.
#@load http/detect-webapps