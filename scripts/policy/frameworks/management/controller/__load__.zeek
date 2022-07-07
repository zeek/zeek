##! The entry point for the Management framework's cluster controller. It runs
##! bootstrap logic for launching a controller process via Zeek's Supervisor.

# When the user sources this from other scripts, the intent may not be just to
# create a controller, but also access Management framework infrastructure, for
# example to reconfigure ports and other settings. So we always load that
# infrastructure, but initiate the controller launch only when this is actually
# the Supervisor process.

@if ( Supervisor::is_supervised() )
@load policy/frameworks/management/controller/config
@endif

@if ( Supervisor::is_supervisor() )
@load ./boot
@endif
