// Taken with permission from:
//
// p0f - passive OS fingerprinting (GNU LESSER GENERAL PUBLIC LICENSE)
// -------------------------------------------------------------------
//
// "If you sit down at a poker game and don't see a sucker,
// get up. You're the sucker."
//
// (C) Copyright 2000-2003 by Michal Zalewski <lcamtuf@coredump.cx>

#ifndef osfinger_h
#define osfinger_h

#include "util.h"
#include "Dict.h"
#include "Reporter.h"
#include "IPAddr.h"

// Size limit for size wildcards.
#define PACKET_BIG 100

// Maximum number of signatures allowed in the config file.
#define MAXSIGS 1024

// Max signature line length.
#define MAXLINE 1024

// Maximum distance from a host to be taken seriously. Between 35 and 64
// is sane. Making it too high might result in some (very rare) false
// positives, too low will result in needless UNKNOWNs.
#define MAXDIST 40

// Maximum number of TCP options.  A TCP packet can have at most 64 bytes
// of header, 20 of which are non-options.  Thus, if a single option
// consumes 1 bytes (the minimum, there can only be 44 bytes of options.
// We err on the safe side.
#define MAXOPT 64

declare(PDict,int);

struct os_type {
	const char* os;
	char* desc;
	uint8 dist;
	uint16 gadgets;
	uint16 match;
	uint32 uptime;
};

struct fp_entry {
	struct fp_entry* next;
	char* os;		// OS genre
	char* desc;		// OS description
	uint8 no_detail;	// disable guesstimates
	uint8 generic;		// generic hit
	uint8 userland;		// userland stack
	uint16 wsize;		// window size
	uint8 wsize_mod;	// MOD_* for wsize
	uint8 ttl;		// TTL
	uint8 df;		// don't fragment bit
	uint8 zero_stamp;	// timestamp option but zero value?
	uint16 size;		// packet size
	uint8 optcnt;		// option count
	uint8 opt[MAXOPT];	// TCPOPT_*
	uint16 wsc;		// window scaling option
	uint16 mss;		// MSS option
	uint8 wsc_mod;		// modulo for WSCALE (NONE or CONST)
	uint8 mss_mod;		// modulo for MSS (NONE or CONST)
	uint32 quirks;		// packet quirks and bugs
	uint32 line;		// config file line
};

struct mtu_def {
	uint16 mtu;
	char* dev;
};

enum FingerprintMode {
	SYN_FINGERPRINT_MODE, SYN_ACK_FINGERPRINT_MODE, RST_FINGERPRINT_MODE,
};

class OSFingerprint {
public:
	OSFingerprint(FingerprintMode mode);
	~OSFingerprint()	{}

	bool Error() const	{ return err; }

	int FindMatch(struct os_type* retval, uint16 tot, uint8 DF_flag,
		uint8 TTL, uint16 WSS, uint8 ocnt, uint8* op, uint16 MSS,
		uint8 win_scale, uint32 tstamp, uint32 quirks, uint8 ECN) const;
	bool CacheMatch(const IPAddr& addr, int id);

	int Get_OS_From_SYN(struct os_type* retval,
			uint16 tot, uint8 DF_flag, uint8 TTL, uint16 WSS,
			uint8 ocnt, uint8* op, uint16 MSS, uint8 win_scale,
			uint32 tstamp, /* uint8 TOS, */ uint32 quirks,
			uint8 ecn) const;

	void load_config(const char* file);

protected:
	void collide(uint32 id);

	void Error(const char* msg)
		{
		reporter->Error("%s", msg);
		err = true;
		}

	void Error(const char* msg, int n)
		{
		reporter->Error(msg, n);
		err = true;
		}

	void Error(const char* msg, const char* s)
		{
		reporter->Error(msg, s);
		err = true;
		}

private:
	bool err;	// if true, a fatal error has occurred
	unsigned int mode;
	uint32 sigcnt, gencnt;
	uint8 problems;
	struct fp_entry sig[MAXSIGS];

	/* By hash */
#define OSHSIZE 16
	struct fp_entry* bh[OSHSIZE];

	PDict(int) os_matches;
};

#define SIGHASH(tsize, optcnt, q, df) \
	((uint8(((tsize) << 1) ^ ((optcnt) << 1) ^ (df) ^ (q) )) & 0x0f)

#define MOD_NONE	0
#define MOD_CONST	1
#define MOD_MSS		2
#define MOD_MTU		3

#define QUIRK_PAST      0x1 /* P */
#define QUIRK_ZEROID	0x2 /* Z */
#define QUIRK_IPOPT	0x4 /* I */
#define QUIRK_URG	0x8 /* U */
#define QUIRK_X2	0x10 /* X */
#define QUIRK_ACK	0x20 /* A */
#define QUIRK_T2	0x40 /* T */
#define QUIRK_FLAGS	0x80 /* F */
#define QUIRK_DATA	0x100 /* D */
#define QUIRK_BROKEN	0x200 /* ! */
#define QUIRK_RSTACK	0x400 /* K */
#define QUIRK_SEQEQ	0x800 /* Q */
#define QUIRK_SEQ0      0x1000 /* 0 */

#define GADGETNAT       0x1
#define GADGETNAT2      0x2
#define GADGETFIREWALL  0x4
#define GADGETECN       0x8
#define GADGETUPTIME    0x10

#define MATCHGENERIC    0x1
#define MATCHFUZZY      0x2

#endif
