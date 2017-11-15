import logging
import threading
import collections

import msgpack
import msgpack.fallback as m_fallback

# import synapse.glob as s_glob

logger = logging.getLogger(__name__)

# A private packer object which is tested for class type & warnings
_pakr = msgpack.Packer(use_bin_type=True, encoding='utf8')
if isinstance(_pakr, m_fallback.Packer):  # pragma: no cover
    logger.warning('msgpack is using the pure python fallback implementation. This will impact performance negatively.')

pdict = collections.defaultdict(msgpack.Packer, use_bin_type=True, encoding='utf8')

def cullPackers():
    '''
    Cull packer objects so dead threads no longer have a packer object
    which is occupying memory.
    '''
    pthreads = list(pdict.keys())
    current_threads = {thr.ident for thr in threading.enumerate()}
    for thread in pthreads:
        if thread not in current_threads:
            pdict.pop(thread)

# Pulling in s_glob throws an import loop becuase its pulled into s_common :(
# s_glob.sched.loop(60, cullPackers)

def getPakr():
    '''
    Get the Packer for the current thread.

    Returns:
        msgpack.Packer: A thread-local packer object.
    '''
    iden = threading.get_ident()
    return pdict[iden]

def en(item):
    '''
    Use msgpack to serialize a compatible python object.

    Args:
        item (obj): The object to serialize

    Returns:
        bytes: The serialized bytes
    '''
    pakr = getPakr()
    try:
        return pakr.pack(item)
    except Exception as e:
        pakr.reset()
        raise

def un(byts):
    '''
    Use msgpack to de-serialize a python object.

    Args:
        byts (bytes): The bytes to de-serialize

    Returns:
        obj: The de-serialized object
    '''
    return msgpack.loads(byts, use_list=False, encoding='utf8')

def iterfd(fd):
    '''
    Generator which unpacks a file object of msgpacked content.

    Args:
        fd: File object to consume data from.

    Yields:
        Objects from a msgpack stream.
    '''
    unpk = msgpack.Unpacker(fd, use_list=False, encoding='utf8')
    for mesg in unpk:
        yield mesg

class Unpk:
    '''
    An extension of the msgpack streaming Unpacker which reports sizes.
    '''
    def __init__(self):
        self.size = 0
        self.unpk = msgpack.Unpacker(use_list=0, encoding='utf8')

    def feed(self, byts):
        '''
        Feed bytes to the unpacker and return completed objects.
        '''
        self.unpk.feed(byts)

        def sizeof(b):
            self.size += len(b)

        retn = []

        while True:

            try:
                item = self.unpk.unpack(write_bytes=sizeof)
                retn.append((self.size, item))
                self.size = 0

            except msgpack.exceptions.OutOfData:
                break

        return retn
