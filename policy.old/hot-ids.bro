# @(#) $Id: hot-ids.bro 785 2004-11-24 05:56:06Z rwinslow $ (LBL)

# If these ids are seen, the corresponding connection is terminated.
const forbidden_ids = {
	"uucp", "daemon", "rewt", "nuucp",
	"EZsetup", "OutOfBox", "4Dgifts",
	"ezsetup", "outofbox", "4dgifts", "sgiweb",
	"r00t", "ruut", "bomb", "backdoor",
	"bionic", "warhead", "check_mate", "checkmate", "check_made",
	"themage", "darkmage", "y0uar3ownd", "netfrack", "netphrack",
} &redef;

const forbidden_ids_if_no_password = { "lp" } &redef;

const forbidden_id_patterns = /(y[o0]u)(r|ar[e3])([o0]wn.*)/ &redef;

const always_hot_ids = {
	"sync", "tutor", "tour",
	"retro", "milk", "moof", "own", "gdm", "anacnd",
	"lp", "demos", forbidden_ids,
} &redef;

# The ones here that aren't in always_hot_ids are only hot upon
# success.
const hot_ids = {
	"root", "system", "smtp", "sysadm", "diag", "sysdiag", "sundiag",
	"operator", "sys", "toor", "issadmin", "msql", "sysop", "sysoper",
	"wank", always_hot_ids,
} &redef;
