import atexit

from AsciiLogSpec import *
from DsLogSpec import *
from OldConnLogSpec import *

from BroLogUtil import *

BroLogUtil.register_type('conn.log', OldConnLogSpec)
BroLogUtil.register_type('log', AsciiLogSpec)
BroLogUtil.register_type('log.gz', AsciiLogSpec)
BroLogUtil.register_type('log.bz2', AsciiLogSpec)
BroLogUtil.register_type('ds', DsLogSpec)

atexit.register(DsLogSpec.cleanup)

