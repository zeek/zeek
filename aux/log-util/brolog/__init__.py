import atexit

from AsciiLogSpec import AsciiLogSpec
from DsLogSpec import DsLogSpec
from OldConnLogSpec import OldConnLogSpec

from BroLogUtil import BroLogUtil

BroLogUtil.register_type('conn.log', OldConnLogSpec)
BroLogUtil.register_type('log', AsciiLogSpec)
BroLogUtil.register_type('log.gz', AsciiLogSpec)
BroLogUtil.register_type('log.bz2', AsciiLogSpec)
BroLogUtil.register_type('ds', DsLogSpec)

atexit.register(DsLogSpec.cleanup)

