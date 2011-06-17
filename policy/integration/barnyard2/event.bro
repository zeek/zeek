## This is the event that Barnyard2 instances will send if they're 
## configured with the bro_alert output plugin.
global barnyard_alert: event(id: Barnyard2::PacketID, alert: Barnyard2::AlertData, msg: string, data: string);
