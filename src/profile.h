
#ifndef BRO_PROFILE_H
#define BRO_PROFILE_H

enum ProfileType {
    PROFILE_NONE = 0,
	PROFILE_CORE_INIT = 1,
	PROFILE_SCRIPT_INIT = 2,
	PROFILE_NET = 3,
	PROFILE_PROCESSING = 4,
	PROFILE_TOTAL = 5,
	PROFILE_SCRIPT_LAND = 6,
	PROFILE_PROTOCOL_LAND = 7,
	PROFILE_HILTI_LAND_COMPILED_STUBS = 8, // value must match compiler
	PROFILE_HILTI_LAND_COMPILED_CODE = 9, // value must match compiler
    PROFILE_CLEANUP = 10,
    PROFILE_HILTI_LAND = 11,
	PROFILE_SCRIPT_LEGACY_LAND = 12,
	PROFILE_JIT_LAND = 13,
    PROFILE_EVENTS = 14,
	// End-marker.
	PROFILE_COUNT
	};

enum ProfileAction{
	PROFILE_START,
	PROFILE_STOP
};

void profile_update(ProfileType t, ProfileAction a);
void profile_count(ProfileType t);
int  profile_level(ProfileType t);
void profile_print();

#endif

