// $Id$

%module broccoli_intern
%{
// Include the header in the wrapper code.
#include <broccoli.h>

// Broccoli internal struct. Easier to copy that here than to include a bunch
// of Broccoli's internal headers.  
struct bro_record {
    void *val_list;
    int val_len;
};
    
typedef BroRecord bro_record ;

// Builds a 2-tuple (type, object).     
PyObject* makeTypeTuple(int type, PyObject *val)
{
 	PyObject *tuple = PyTuple_New(2);
    PyTuple_SetItem(tuple, 0, PyInt_FromLong(type));
    PyTuple_SetItem(tuple, 1, val);
    return tuple;
}

// Parses a 2-tuple (type, object). Return 1 on success. 
// Borrows input's reference to object.
int parseTypeTuple(PyObject* input, int *type, PyObject **val)
{
    if ( ! (PyTuple_Check(input) && PyTuple_Size(input) == 2) ) {
		PyErr_SetString(PyExc_RuntimeError, "argument must be 2-tuple");
		return 0;
    }
    
	PyObject *ptype = PyTuple_GetItem(input, 0);
	PyObject *pval = PyTuple_GetItem(input, 1);
	
	if ( ! PyInt_Check(ptype) ) {
		PyErr_SetString(PyExc_RuntimeError, "first tuple element must be integer");
		return 0;
    }
    
    *type = PyInt_AsLong(ptype);
    
	if ( *type < 0 || *type > BRO_TYPE_MAX ) {
		PyErr_SetString(PyExc_RuntimeError, "unknown type in tuple");
		return 0;
    }
    
    *val = pval;
    return 1;
}

// Release the memory associated with the Broccoli value.
void freeBroccoliVal(int type, void* data)
{
    if ( ! data )
        return;
    
    switch ( type ) {
      case BRO_TYPE_STRING:
        free(((BroString *)data)->str_val);
        free(data);
        break;
        
      case BRO_TYPE_RECORD:
        bro_record_free((BroRecord *)data);
        break;
        
      default:
        free(data);
    }
    
}

// Converts a Broccoli value into a Python object.
PyObject* valToPyObj(int type, void* data)
{
 	PyObject* val = 0;

	switch (type) {
      case BRO_TYPE_BOOL:
        val = PyBool_FromLong(*((int *)data));   
        break;
        
      case BRO_TYPE_INT:
      case BRO_TYPE_COUNT:
      case BRO_TYPE_COUNTER:
      case BRO_TYPE_IPADDR:
      case BRO_TYPE_NET: {
        val = PyInt_FromLong(*((long *)data));
        break;
      }
        
      case BRO_TYPE_DOUBLE:
      case BRO_TYPE_TIME:
      case BRO_TYPE_INTERVAL: {
          val = PyFloat_FromDouble(*((double *)data));
          break;
      }
        
      case BRO_TYPE_STRING: {
          BroString *str = (BroString*)data;
          val = PyString_FromStringAndSize(str->str_val, str->str_len);
          break;
      }

      case BRO_TYPE_ENUM: {
          val = PyTuple_New(2);
          PyTuple_SetItem(val, 0, PyBool_FromLong(*((int *)data)));
          PyTuple_SetItem(val, 1, PyString_FromString("broccoli-doesnt-give-use-the-enum-type! :-("));
          break;
      }
        
        
      case BRO_TYPE_PORT: {
          BroPort *port = (BroPort*)data;
          val = PyTuple_New(2);
          PyTuple_SetItem(val, 0, PyInt_FromLong(port->port_num));
          PyTuple_SetItem(val, 1, PyInt_FromLong(port->port_proto));
          break;
      }
            
      case BRO_TYPE_SUBNET: {
          BroSubnet *subnet = (BroSubnet*)data;
          val = PyTuple_New(2);
          PyTuple_SetItem(val, 0, PyInt_FromLong(subnet->sn_net));
          PyTuple_SetItem(val, 1, PyInt_FromLong(subnet->sn_width));
          break;
      }
        
      case BRO_TYPE_RECORD: { 
          BroRecord *rec = (BroRecord*)data;
          PyObject *fields = PyList_New(rec->val_len);
          int i;
          for ( i = 0; i < rec->val_len; i++ ) {
              int type = BRO_TYPE_UNKNOWN;
              void *data = bro_record_get_nth_val(rec, i, &type);
              PyList_SetItem(fields, i, valToPyObj(type, data));
          }
          val = fields;
          break;
      }
    
      default:
        PyErr_SetString(PyExc_RuntimeError, "unknown type");
        return 0;
        
    }
    
    return makeTypeTuple(type, val);
}
    
// Converts a Python object into Broccoli value.
int pyObjToVal(PyObject *val, int type, const char **type_name, void** data)
{
	*type_name = 0;
    *data = 0;

    switch (type) {
      case BRO_TYPE_BOOL:
      case BRO_TYPE_INT:
      case BRO_TYPE_COUNT:
      case BRO_TYPE_COUNTER:
      case BRO_TYPE_IPADDR:
      case BRO_TYPE_NET: {
          int* tmp = (int *)malloc(sizeof(int));
		  *tmp = PyInt_AsLong(val);
          *data = tmp;
          break;
      }
        
      case BRO_TYPE_DOUBLE:
      case BRO_TYPE_TIME:
      case BRO_TYPE_INTERVAL: {
          double* tmp = (double *)malloc(sizeof(double));
		  *tmp = PyFloat_AsDouble(val);
          *data = tmp;
          break;
      }

      case BRO_TYPE_STRING: {
          BroString* str = (BroString *)malloc(sizeof(BroString));
          
          const char* tmp = PyString_AsString(val);
          if ( ! tmp )
              return 0;
          
          str->str_len = strlen(tmp);
          str->str_val = strdup(tmp);
          *data = str;
          break;
      }

      case BRO_TYPE_ENUM: {
          if ( ! (PyTuple_Check(val) && PyTuple_Size(val) == 2) ) {
              PyErr_SetString(PyExc_RuntimeError, "enum must be 2-tuple");
              return 0;
          }
          
          int* tmp = (int *)malloc(sizeof(int));
		  *tmp = PyInt_AsLong(PyTuple_GetItem(val, 0));
          *data = tmp;
          
          const char* enum_type = PyString_AsString(PyTuple_GetItem(val, 1));
          if ( ! enum_type )
              return 0;
          
          *type_name = strdup(enum_type);
          break;
      }
        
      case BRO_TYPE_PORT: {
          if ( ! (PyTuple_Check(val) && PyTuple_Size(val) == 2) ) {
              PyErr_SetString(PyExc_RuntimeError, "port must be 2-tuple");
              return 0;
          }
    
          BroPort* port = (BroPort *)malloc(sizeof(BroPort));
          port->port_num = PyInt_AsLong(PyTuple_GetItem(val, 0));
          port->port_proto = PyInt_AsLong(PyTuple_GetItem(val, 1));
          *data = port;
          break;
      }
            
      case BRO_TYPE_SUBNET: {
          if ( ! (PyTuple_Check(val) && PyTuple_Size(val) == 2) ) {
              PyErr_SetString(PyExc_RuntimeError, "subnet must be 2-tuple");
              return 0;
          }
    
          BroSubnet* subnet = (BroSubnet *)malloc(sizeof(BroSubnet));
          subnet->sn_net = PyInt_AsLong(PyTuple_GetItem(val, 0));
          subnet->sn_width = PyInt_AsLong(PyTuple_GetItem(val, 1));
          *data = subnet;
          break;
      }
        
      case BRO_TYPE_RECORD: {
          BroRecord *rec = bro_record_new();
          int i;
          for ( i = 0; i < PyList_Size(val); i++ ) {
              int ftype;
              PyObject *fval;
              if ( ! parseTypeTuple(PyList_GetItem(val, i), &ftype, &fval) )
                  return 0;
                  
              const char *ftype_name;
              void *fdata;
              if ( ! pyObjToVal(fval, ftype, &ftype_name, &fdata) ) 
                  return 0;
              
              bro_record_add_val(rec, "<unknown>", ftype, 0, fdata);
              freeBroccoliVal(ftype, fdata);
          }
          
          *data = rec;
          break;
      }
        
      default:
        PyErr_SetString(PyExc_RuntimeError, "unknown type");
        return 0;
    }
    
    return 1;
}

// C-level event handler for events. We register all events with this callback,
// passing the target Python function in via data. 
void event_callback(BroConn *bc, void *data, BroEvMeta *meta)
{
    PyObject *func = (PyObject*)data;
    
	int i;
	PyObject *pyargs = PyTuple_New(meta->ev_numargs);
	for ( i = 0; i < meta->ev_numargs; i++ )
		PyTuple_SetItem(pyargs, i, valToPyObj(meta->ev_args[i].arg_type, meta->ev_args[i].arg_data));
	
	PyObject *result = PyObject_Call(func, pyargs, 0);

    Py_DECREF(pyargs);
    
    if ( result )
	    Py_DECREF(result);
}

%}

// For bro_event_registry_add_compact().
%typemap(in) (BroCompactEventFunc func, void *user_data)
{
    if ( ! PyFunction_Check($input) ) {
        PyErr_SetString(PyExc_RuntimeError, "callback must be a function");
        return NULL;
    }
    
	$1 = event_callback;
	$2 = $input;
    Py_INCREF($input);
}

// For bro_event_add_val() and bro_record_add_val().
%typemap(in) (int type, const char *type_name, const void *val)
{
    int type;
    const char* type_name;
    void *data;

    PyObject *val;

//bro_debug_messages = 1;
//bro_debug_calltrace = 1;


    if ( ! parseTypeTuple($input, &type, &val) )
        return NULL;
    
    if ( ! pyObjToVal(val, type, &type_name, &data) )
        return NULL;
    
    $1 = type;
    $2 = type_name;
    $3 = data;
}

%typemap(freearg) (int type, const char *type_name, const void *val)
{
    // Broccoli makes copies of the passed data so we need to clean up.
    freeBroccoliVal($1, $3);
    
    if ( $2 )
        free($2);
}

///// The following is a subset of broccoli.h for which we provide wrappers. 

#define BRO_TYPE_UNKNOWN           0
#define BRO_TYPE_BOOL              1
#define BRO_TYPE_INT               2
#define BRO_TYPE_COUNT             3
#define BRO_TYPE_COUNTER           4
#define BRO_TYPE_DOUBLE            5
#define BRO_TYPE_TIME              6
#define BRO_TYPE_INTERVAL          7
#define BRO_TYPE_STRING            8
#define BRO_TYPE_PATTERN           9
#define BRO_TYPE_ENUM             10
#define BRO_TYPE_TIMER            11
#define BRO_TYPE_PORT             12
#define BRO_TYPE_IPADDR           13
#define BRO_TYPE_NET              14
#define BRO_TYPE_SUBNET           15
#define BRO_TYPE_ANY              16
#define BRO_TYPE_TABLE            17
#define BRO_TYPE_UNION            18
#define BRO_TYPE_RECORD           19
#define BRO_TYPE_LIST             20
#define BRO_TYPE_FUNC             21
#define BRO_TYPE_FILE             22
#define BRO_TYPE_VECTOR           23
#define BRO_TYPE_ERROR            24
#define BRO_TYPE_PACKET           25 
#define BRO_TYPE_SET              26
#define BRO_TYPE_MAX              27
#define BRO_CFLAG_NONE                      0
#define BRO_CFLAG_RECONNECT           (1 << 0)
#define BRO_CFLAG_ALWAYS_QUEUE        (1 << 1)
#define BRO_CFLAG_SHAREABLE           (1 << 2)
#define BRO_CFLAG_DONTCACHE           (1 << 3)
#define BRO_CFLAG_YIELD               (1 << 4)
#define BRO_CFLAG_CACHE               (1 << 5)

// The exact types of these don't really matter as we're only
// passing pointers around.
typedef void BroCtx;
typedef void BroConn;
typedef void BroEvent;

int            bro_init(const BroCtx *ctx);
BroConn       *bro_conn_new_str(const char *hostname, int flags);
void           bro_conn_set_class(BroConn *bc, const char *classname);
int            bro_conn_connect(BroConn *bc);
int            bro_conn_process_input(BroConn *bc);
int            bro_event_queue_length(BroConn *bc);
BroEvent      *bro_event_new(const char *event_name);
void           bro_event_free(BroEvent *be);
int            bro_event_add_val(BroEvent *be, int type, const char *type_name,const void *val);
int            bro_event_send(BroConn *bc, BroEvent *be);
void           bro_event_registry_add_compact(BroConn *bc, const char *event_name, BroCompactEventFunc func, void *user_data);
double         bro_util_current_time(void);
                          
