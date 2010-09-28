// $Id: SubnetTree.cc 6813 2009-07-07 18:54:12Z robin $

#include <memory.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>

#include "SubnetTree.h"

static PyObject* dummy = Py_BuildValue("s", "<dummy string>");

inline static prefix_t* make_prefix(unsigned long addr, int width)
	{
	prefix_t* subnet = new prefix_t;

	memcpy(&subnet->add.sin, &addr, sizeof(subnet->add.sin)) ;
	subnet->family = AF_INET;
	subnet->bitlen = width;
	subnet->ref_count = 1;

	return subnet;
	}

inline static bool parse_cidr(const char *cidr, unsigned long *subnet, unsigned short *mask)
{
    static char buffer[32];
    struct in_addr addr;

    if ( ! cidr )
        return false;

    const char *s = strchr(cidr, '/');
    if ( s ) {
        int len = s - cidr < 32 ? s - cidr : 31;
        memcpy(buffer, cidr, len);
        buffer[len] = '\0';
        *mask = atoi(s+1);
        s = buffer;
    }
    else {
        s = cidr;
        *mask = 32;
    }

    if ( ! inet_aton(const_cast<char *>(s), &addr) )
        return false;

    *subnet = addr.s_addr;

    return true;

}

SubnetTree::SubnetTree()
{
    tree = New_Patricia(128);
}

SubnetTree::~SubnetTree()
{
    Destroy_Patricia(tree, 0);
}

bool SubnetTree::insert(const char *cidr, PyObject* data) 
{
    unsigned long subnet;
    unsigned short mask;

    if ( ! parse_cidr(cidr, &subnet, &mask) )
        return false;

    return insert(subnet, mask, data);
}

bool SubnetTree::insert(unsigned long subnet, unsigned short mask, PyObject* data)
{
	prefix_t* sn = make_prefix(subnet, mask);
	patricia_node_t* node = patricia_lookup(tree, sn);
	Deref_Prefix(sn);

	if ( ! node ) {
        fprintf(stderr, "Cannot create node in patricia tree");
        return false;
    }

    if ( ! data )
        data = dummy;

    Py_INCREF(data);
	node->data = data;

	return true;
}

bool SubnetTree::remove(const char *cidr)
{
    unsigned long subnet;
    unsigned short mask;

    if ( ! parse_cidr(cidr, &subnet, &mask) )
        return false;

    return remove(subnet, mask);
}

bool SubnetTree::remove(unsigned long addr, unsigned short mask)
{                                      /*  */
	prefix_t* subnet = make_prefix(addr, mask);
	patricia_node_t* node = patricia_search_exact(tree, subnet);
	Deref_Prefix(subnet);

	if ( ! node )
		return false;

    PyObject* data = (PyObject*)node->data;
    Py_DECREF(data);

	patricia_remove(tree, node);

	return data != dummy;
}

PyObject* SubnetTree::lookup(const char *cidr, int size) const
{
    struct in_addr a;

    if ( ! cidr )
        return false;

    // If it's a 4-byte string, it's probably a host address packed with
    // socket.inet_aton().
    if ( size == 4 )
        return lookup(*((unsigned long *)cidr));

    if ( ! inet_aton(cidr, &a) )
        return false;

    return lookup(a.s_addr);
}

PyObject* SubnetTree::lookup(unsigned long addr) const
{
	prefix_t* subnet = make_prefix(addr, 32);
	patricia_node_t* node =	patricia_search_best(tree, subnet);
	Deref_Prefix(subnet);

    if ( ! node )
        return 0;

    PyObject* data = (PyObject*)node->data;

    Py_INCREF(data);
    return data;
}

