
import socket
import struct
from types import FunctionType 

from _broccoli_intern import *

bro_init(None)

##### Connection class which capsulates a Broccoli connection.
class Connection:
    # Connection to destination given as string "host:port"
    def __init__(self, destination, broclass="", flags=BRO_CFLAG_RECONNECT | BRO_CFLAG_ALWAYS_QUEUE, connect=True):
        self.bc = bro_conn_new_str(destination, flags)
        self.destination = destination
        if not self.bc:
            raise IOError("cannot init Broccoli connection handle")
        
        self._registerHandlers()
        
        if broclass:
            bro_conn_set_class(self.bc, broclass)
        
        if connect:
            self.connect();

    # If the instance was created with connect=False, this will trigger the connect.
    def connect(self):
        if not bro_conn_connect(self.bc):
            raise IOError("cannot connect to %s" % self.destination)
        
    # Hand control to Broccoli's I/O loop.
    # Returns true if the send queue is non-empty.
    def processInput(self):
        bro_conn_process_input(self.bc);
        return bro_event_queue_length(self.bc) > 0

    # Send an event of name with args.
    def send(self, name, *args):
        ev = bro_event_new(name)
        for arg in args:
            bro_event_add_val(ev, _getInternalVal(arg));
            
        bro_event_send(self.bc, ev);
        bro_event_free(ev);
        self.processInput()
        
    # Explicit subscribe
    def subscribe(self, event_name, callback):
        ev = event(callback)
        bro_event_registry_add_compact(self.bc, event_name, ev);

    # Register all decorated event callbacks.
    def _registerHandlers(self):
        for ev in _Events:
            bro_event_registry_add_compact(self.bc, ev.__name__, ev);

            
##### Wrapped helper functions.        
def current_time():
    return bro_util_current_time()

##### Decorator @event(val-type1, val-type2, val-type3, ...)

# List of all functions declared with the @event decorator 
# (more precisely, list of all of their wrappers; see below).
_Events = []

def event(*types):

    # We wrap the event callback into a function which turns the 2-tuples (type,val)
    # that we get from the C layer into the corresponding Python object.
    def make_wrapper(func):
        
        def wrapped_f(*args):
            
	    new_args = []
            
            ptypes = types
            if not ptypes:
                # Allow omitting types. 
                ptypes =  [None] *len(args)
                
            for (arg, type) in zip(args, ptypes):
                # Split the 2-tuples passed to us by the C layer.
                (btype, val) = arg
                # Create an instance of the corresponding Python type.
		new_args += [instantiate(btype, val, type)]
                
            # Finally call the callback.
	    return func(*new_args);

        # Pretend the wrapper has the name of the actual callback (rather than "wrapped_f" ...)
	wrapped_f.func_name = func.func_name
	
        # Add the wrapped function to the list of events handlers.
        global _Events
        _Events += [wrapped_f]
            
        return wrapped_f

    # Allow @event instead of @event()
    if len(types) == 1 and type(types[0]) == FunctionType:
        func = types[0]
        types = ()
        return make_wrapper(func)
    
    else:
        return make_wrapper

##### Data types

# For those Bro types which do not direcly correspond to Python type, we create
# wrapper classes. For those which do (int, float), we use the Python type directly.

# Base class for our wrapper classes.
# For atomic types, the classes here act as both type and instances. For non-atomic
# types (i.e., records) we define separate type and instance classes below. 
class Val:
    # Type is the Bro type BRO_TYPE_*.
    # Val is representation of the Val in a standard Python type. 
    def __init__(self, type, val):
        self.type = type
        self.val = val
        
        self.__class__._bro_type = type # Doing it once would be sufficient.

    def __str__(self):
	return str(self.val)
	
    # Convert value into a 2-tuple (type, val) as expected by the C layer.
    def internalVal(self):
        return (self.type, self.val)
    
class count(Val):
    def __init__(self, val):
        Val.__init__(self, BRO_TYPE_COUNT, int(val))

    @staticmethod
    def _factory(val, dst_type):
        v = count(val)
        if dst_type == int or not dst_type:
            return v.val
        _typeCheck(dst_type, count)
        return v

class interval(Val):
    def __init__(self, val):
        Val.__init__(self, BRO_TYPE_INTERVAL, float(val))
	
    @staticmethod
    def _factory(val, dst_type):
        v = interval(val)
        if dst_type == float or not dst_type:
            return v.val
        _typeCheck(dst_type, interval)
        return v

class time(Val):
    def __init__(self, val):
        Val.__init__(self, BRO_TYPE_TIME, float(val))
	
    @staticmethod
    def _factory(val, dst_type):
        v = time(val)
        if dst_type == float or not dst_type:
            return v.val
        _typeCheck(dst_type, time)
        return v

class port(Val):
    
    protos_by_name = { "tcp": 6, "udp": 17, "icmp": 1 }
    protos_by_num =  { 6: "tcp", 17: "udp", 1: "icmp" }
    
    def __init__(self, str=None, internal=None):
        v = internal and internal or self._parse(str)
        Val.__init__(self, BRO_TYPE_PORT, v)

    def __str__(self):
        (port, proto) = self.val
        try:
            return "%d/%s" % (port, self.protos_by_num[proto])
        except IndexError:
            return "%s/unknown" % port
        
    @staticmethod
    def _factory(val, dst_type):
        v = port(internal=val)
        if dst_type == str or not dst_type:
            return str(v)
        if dst_type == int:
            return v[0]
        _typeCheck(dst_type, port)
        return v
    
    def _parse(self, str):
        (port, proto) = str.split("/")
        try:
            return (int(port), self.protos_by_name[proto.lower()])
        except (IndexError, ValueError):
            return (0, 0)
        
class addr(Val):
    def __init__(self, str=None, internal=None):
        v = internal and internal or self._parse(str)
        Val.__init__(self, BRO_TYPE_IPADDR, v)

    def __str__(self):
        return socket.inet_ntoa(struct.pack('=l', self.val))
        
    @staticmethod
    def _factory(val, dst_type):
        v = addr(internal=val)
        if dst_type == str or not dst_type:
            return str(v)
        _typeCheck(dst_type, addr)
        return v
    
    def _parse(self, str):
        return struct.unpack('=l',socket.inet_aton(str))[0]

# Not supported at this point. Need to write a parse function.
class net(Val):
    def __init__(self, str=None, internal=None):
        v = internal and internal or self._parse(str)
        Val.__init__(self, BRO_TYPE_NET, v)

    def __str__(self):
        return "X.X.X"  # FIXME
        
    @staticmethod
    def _factory(val, dst_type):
        v = net(internal=val)
        if dst_type == str or not dst_type:
            return str(v)
        _typeCheck(dst_type, net)
        return v
    
    def _parse(self, str):
        return 0   # FIXME

class subnet(Val):
    def __init__(self, str=None, internal=None):
        v = internal and internal or self._parse(str)
        Val.__init__(self, BRO_TYPE_SUBNET, v)

    def __str__(self):
        (net, mask) = self.val
        return "%s/%d" % (socket.inet_ntoa(struct.pack('=l', net)), mask)
    
    @staticmethod
    def _factory(val, dst_type):
        v = subnet(internal=val)
        if dst_type == str or not dst_type:
            return str(v)
        _typeCheck(dst_type, subnet)
        return v
    
    def _parse(self, str):
        (net, mask) = str.split("/")
        return (struct.unpack('=l',socket.inet_aton(net))[0], int(mask))

# Not supported at this point since Broccoli seems to have problems with
# enums. Also need to write parse functions.
class enum(Val):
    def __init__(self, str=None, internal=None):
        v = internal and internal or self._parse(str)
        Val.__init__(self, BRO_TYPE_ENUM, v)

    def __str__(self):
        return "XXXX"  # FIXME
        
    @staticmethod
    def _factory(val, dst_type):
        v = enum(internal=val)
        _typeCheck(dst_type, enum)
        return v
    
    def _parse(self, str):
        return 0   # FIXME
    
# Helper class for unset values.    
class unknown(Val):        
    def __init__(self):
        Val.__init__(self, BRO_TYPE_UNKNOWN, None)

# Dictionary of all defined record types.         
RecTypes = {}

# Type class for records, which maps field names to indices.
# E.g., conn_id = record_type("orig_h", "orig_p", "resp_h", "resp_p")
class record_type:
    def __init__(self, *fields):
        self.fields = fields
	
	global RecTypes
        # Remember this type by its name.
	RecTypes[self.__class__.__name__] = self

    @classmethod
    def _factory(self, vals, dst_type):
        # FIXME: Add _typeCheck(),
        # FIXME: For recursive records we'd need to pass the right record type
        # here instead of none, which we don't have. How to do that?
        
        # Get the type.
        rec_type = RecTypes[dst_type.__class__.__name__]
        
        # Init the field values.
        vals = [instantiate(btype, val, None) for (btype, val) in vals]
        
	return record(rec_type, vals)

# Class for record instances.
class record(Val):
    def __init__(self, type, vals = None):
        Val.__init__(self, BRO_TYPE_RECORD, {})
        
        # Save the record's type.
	self._type = type

        if not vals:
            # Use Nones if we didn't get any values.
            vals = [None] * len(type.fields)

        # Initialize record fields.
        for (key, val) in zip(type.fields, vals):
            self.val[key] = val
                
    def internalVal(self):
        vals = [_getInternalVal(self.val.get(f, unknown())) for f in self._type.fields]
        return (BRO_TYPE_RECORD, vals)

    # Provide attribute access via "val.attr".
    def __getattr__(self, key):
        if "_type" in self.__dict__ and key in self._type.fields:
            return self.val[key]
        raise AttributeError
        
    def __setattr__(self, key, val):
        try:
            if key in self._type.fields:
                self.val[key] = val
                return
        except AttributeError:
            pass

        # FIXME: Check that key is defined in type.
        self.__dict__[key] = val

# Helper to check whether two Python types match.
def _typeCheck(type1, type2):
    def typeToBro(type):
        # Do the Python types manually.
        if type == int:
            return BRO_TYPE_INT;
        if type == bool:
            return BRO_TYPE_BOOL;
        if type == float:
            return BRO_TYPE_DOUBLE;
        if type == str:
            return BRO_TYPE_STRING;
        return type._bro_type
    
    if type1 and type2 and typeToBro(type1) != typeToBro(type2):
        raise TypeError

# Helper to create the 2-tuple val.
def _getInternalVal(arg):

    if arg == None:
        raise ValueError("uninitialized event argument")

    if type(arg) == int:
        return (BRO_TYPE_INT, arg)
    elif type(arg) == bool:
        return (BRO_TYPE_BOOL, arg)
    elif type(arg) == str:
        return(BRO_TYPE_STRING, arg)
    elif type(arg) == float:
        return(BRO_TYPE_DOUBLE, arg)
    else:
        return arg.internalVal()
    
# Factories for Python internal types.
def _int_factory(val, dst_type):
    return int(val)

def _bool_factory(val, dst_type):
    return bool(val)

def _string_factory(val, dst_type):
    return str(val)

def _float_factory(val, dst_type):
    return float(val)

string = str    
double = float

# Table of factories for all supported types so that we can dynamically
# instantiate them.
_Factories = {
    BRO_TYPE_INT: _int_factory,
    BRO_TYPE_BOOL: _bool_factory,
    BRO_TYPE_COUNT: count._factory,
    BRO_TYPE_TIME: time._factory,
    BRO_TYPE_INTERVAL: interval._factory,
    BRO_TYPE_DOUBLE: _float_factory,
    BRO_TYPE_STRING: _string_factory,
    BRO_TYPE_PORT: port._factory,
    BRO_TYPE_IPADDR: addr._factory,
    BRO_TYPE_NET: net._factory,
    BRO_TYPE_SUBNET: subnet._factory,
    BRO_TYPE_ENUM: enum._factory,
    BRO_TYPE_RECORD: record_type._factory,
}

def instantiate(src_type, val, dst_type):
    return _Factories[src_type](val, dst_type)

        


