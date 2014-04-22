##! This file is separate from the base script so that dependencies can
##! be loaded in the correct order.

module Barnyard2;

export {
	type AlertData: record {
		sensor_id:          count;  ##< Sensor that originated this event.
		ts:                 time;   ##< Timestamp attached to the alert.
		signature_id:       count;  ##< Sig id for this generator.
		generator_id:       count;  ##< Which generator generated the alert?
		signature_revision: count;  ##< Sig revision for this id.
		classification_id:  count;  ##< Event classification.
		classification:     string; ##< Descriptive classification string.
		priority_id:        count;  ##< Event priority.
		event_id:           count;  ##< Event ID.
	} &log;

	type PacketID: record {
		src_ip: addr;
		src_p: port;
		dst_ip: addr;
		dst_p: port;
	} &log;

	## This is the event that Barnyard2 instances will send if they're 
	## configured with the bro_alert output plugin.
	global barnyard_alert: event(id: Barnyard2::PacketID,
	                             alert: Barnyard2::AlertData,
	                             msg: string,
	                             data: string);
}
