# $Id:$
#
# Changes the class for addresses that have generated alerts.

@load time-machine
@load notice
@load scan

event notice_alarm(n: notice_info, action: NoticeAction)
	{
	if ( ! n?$src )
		return;

	if ( n?$conn && is_external_connection(n$conn) )
		return;

	local class = "alarm";
	if ( n$note == Scan::AddressScan || n$note == Scan::PortScan )
		class = "scanner";

	TimeMachine::set_class(n$src, class, TimeMachine::BOTH, "tm-class");
	}
