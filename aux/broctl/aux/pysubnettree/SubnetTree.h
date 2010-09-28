// $Id: SubnetTree.h 6813 2009-07-07 18:54:12Z robin $

extern "C" {
#include "Python.h"
#include "patricia.h"
}

#ifdef SWIG
// If a function is supposed to accept 4-byte tuples as packet by
// socket.inet_aton(), it needs to accept strings which contain 0s.
// Therefore, we need a size parameter.
%apply (char *STRING, int LENGTH) { (char *cidr, int size) };
#endif

class SubnetTree
{
public:
   SubnetTree();
   ~SubnetTree();

   bool insert(const char *cidr, PyObject* data = 0);
   bool insert(unsigned long subnet, unsigned short mask, PyObject* data = 0);

   bool remove(const char *cidr);
   bool remove(unsigned long subnet, unsigned short mask);

   PyObject* lookup(const char *cidr, int size) const;
   PyObject* lookup(unsigned long addr) const;

#ifndef SWIG   
   bool operator[](const char* addr) const { return lookup(addr, strlen(addr)); }
   bool operator[](unsigned long addr) const { return lookup(addr); }
#else
   %extend {
       PyObject* __contains__(char *cidr, int size) 
       {
           if ( ! cidr ) {
               PyErr_SetString(PyExc_TypeError, "index must be string");
               return 0;
           }

           PyObject* obj = self->lookup(cidr, size);
           if ( obj )
               Py_DECREF(obj);

           if ( obj != 0 )
               Py_RETURN_TRUE;
           else
               Py_RETURN_FALSE;
       }

       bool __contains__(unsigned long addr) 
       {
           return self->lookup(addr);
       }

       PyObject* __getitem__(char *cidr, int size) 
       {
           if ( ! cidr ) {
               PyErr_SetString(PyExc_TypeError, "index must be string");
               return 0;
           }

           PyObject* data = self->lookup(cidr, size);
           if ( ! data ) {
               PyErr_SetString(PyExc_KeyError, cidr ? cidr : "None");
               return 0;
           }

           return data;
       }

       PyObject*  __setitem__(const char* cidr, PyObject* data) 
       {
           if ( ! cidr ) {
               PyErr_SetString(PyExc_TypeError, "index must be string");
               return 0; 
           }

           if ( ! self->insert(cidr, data) ) {
               PyErr_SetString(PyExc_IndexError, "cannot insert network");
               return 0;
           }

           return PyInt_FromLong(1);
       }

       PyObject* __delitem__(const char* cidr) 
       {
           if ( ! cidr ) {
               PyErr_SetString(PyExc_TypeError, "index must be string");
               return 0; 
           }

           if ( ! self->remove(cidr) ) {
               PyErr_SetString(PyExc_IndexError, "cannot remove network");
               return 0;
           }

           return PyInt_FromLong(1);
       }

   }
#endif   

private:
   patricia_tree_t* tree;

};
