##! Types used by the IGMP packet analyzer plugin

module IGMP;

export {

	## IGMP message types, as defined in :rfc:`3376#section-4`.
	type IgmpMessageType: enum {
		MEMBERSHIP_QUERY     = 0x11,
		MEMBERSHIP_REPORT_V1 = 0x12,
		MEMBERSHIP_REPORT_V2 = 0x16,
		LEAVE_GROUP          = 0x17,
		MEMBERSHIP_REPORT_V3 = 0x22,
		BAD_CHECKSUM         = 0x00
	};

	## IGMP Version 3 Membership Report Group record types, as defined in
	## :rfc:`3376#section-4.2.12`
	type GroupType: enum {
		MODE_IS_INCLUDE        = 1,
		MODE_IS_EXCLUDE        = 2,
		CHANGE_TO_INCLUDE_MODE = 3,
		CHANGE_TO_EXCLUDE_MODE = 4,
		ALLOW_NEW_SOURCES      = 5,
		BLOCK_OLD_SOURCES      = 6
	};

	## IGMP Version 3 Membership Report Group record, as defined in
	## :rfc:`3376#section-4.2`
	type MulticastGroup: record {
		## The type of the multicast record being reported.
		group_type:     GroupType;
		## The length of the auxiliary data field in this group record.
		aux_data_len:   count;
		## The number of source addresses.
		num_sources:    count;
		## The multicase address to which this record pertains.
		multicast_addr: addr;
		## A vector of source addresses.
		sources:        vector of addr;
		## Additional information pertaining to this record.
		aux_data:       string;
	};

}
