# $Id: remote-update.bro 6811 2009-07-06 20:41:10Z robin $
#
# Code to be executed when we're dynamically updated on the fly. 

@load analysis-groups

module RemoteUpdate;

event configuration_update()
	{
	if ( ! is_remote_event() )
		return;
	
	AnalysisGroups::update();
	event remote_log(REMOTE_LOG_INFO, REMOTE_SRC_SCRIPT, "configuration updated");
	}
