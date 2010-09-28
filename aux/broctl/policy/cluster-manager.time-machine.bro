# $Id: cluster-manager.time-machine.bro 6811 2009-07-06 20:41:10Z robin $
#
# Relays TM commands received from the workers  to a TM connected to the 
# manager. Note that potential responses from the TM will go to the manager 
# and are *not* be propapated back to the workers.

event TimeMachine::command(cmd: string)
       {
       if ( is_remote_event() )
               event TimeMachine::command(cmd);
       }


