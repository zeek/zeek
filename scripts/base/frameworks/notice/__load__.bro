@load ./main
@load ./weird

# There should be no overhead imposed by loading notice actions so we
# load them all.
@load ./actions/drop
@load ./actions/email_admin
@load ./actions/page

# Load the script to add hostnames to emails by default.
# NOTE: this exposes a memleak in async DNS lookups.
#@load ./extend-email/hostnames
