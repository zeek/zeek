##! The entry point for the Management framework's cluster agent. It runs
##! bootstrap logic for launching an agent process via Zeek's Supervisor.

# When the user sources this from other scripts, the intent may not be just to
# create an agent, but also access Management framework infrastructure, for
# example to reconfigure ports and other settings. So we always load that
# infrastructure, but initiate the agent launch only when this is actually the
# Supervisor process.

@if ( Supervisor::is_supervised() )
@load policy/frameworks/management/agent/config
@endif

@if ( Supervisor::is_supervisor() )
@load policy/frameworks/management/supervisor
@load ./boot
@endif
