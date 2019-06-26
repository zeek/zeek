@load ./main
@load ./weird

# There should be no overhead imposed by loading notice actions so we
# load them all.
@load ./actions/email_admin
@load ./actions/page
@load ./actions/add-geodata

# Load here so that it can check whether clustering is enabled.
@load ./actions/pp-alarms
