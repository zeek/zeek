@load ./base

# Load the script to add hostnames to emails by default.
# NOTE: this exposes a memleak in async DNS lookups.
#@load ./extend-email/hostnames