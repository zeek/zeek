#ifndef __FILTER_COMMON_H
#define __FILTER_COMMON_H

#include <linux/types.h>

struct five_tuple {
	__u32 ip_source;
	__u32 ip_destination;
	__u16 port_source;
	__u16 port_destination;
	__u8  protocol;
};

#endif /* __FILTER_COMMON_H */
