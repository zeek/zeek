# $Id:$
#
# Forward remote alarms to our local system.

event notice_action(n: notice_info, action: NoticeAction)
	{
	if ( is_remote_event() )
		{
		# Don't raise this event recursively.
		suppress_notice_action = T;
		NOTICE(n);
		suppress_notice_action = F;
		}
	}
