
#ifndef BRO_PROFILE_H
#define BRO_PROFILE_H

enum ProfileType {
	PROFILE_CORE_INIT,
	PROFILE_SCRIPT_INIT,
	PROFILE_NET,
	PROFILE_PROCESSING,
	PROFILE_TOTAL,
	PROFILE_SCRIPT_LAND,
	PROFILE_PROTOCOL_LAND,
	// End-marker.
	PROFILE_COUNT
	};

enum ProfileAction{
	PROFILE_START,
	PROFILE_STOP
};

void profile_update(ProfileType t, ProfileAction a);
void profile_print();

#endif

