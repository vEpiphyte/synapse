import threading

import synapse.glob as s_glob

class CmpSet:
    '''
    The CmpSet class facilitates atomic compare and set.
    '''
    def __init__(self, valu):
        self.valu = valu

    def set(self, valu):
        '''
        Atomically set the valu and return change status.

        Args:
            valu (obj): The new value

        Returns:
            (bool): True if the value changed.
        '''
        with s_glob.lock:
            retn = self.valu != valu
            self.valu = valu
            return retn

class Ready:
    '''
    An atomic inc/dec state counter with a positive edge triggered event.

    Args:
        size (int): Threshold value, which when the internal counter reaches, sets the event.
        valu (int): Initial value of the internal counter.
        lock (threading.Lock): The lock used to protect the counter value.

    Notes:
        The Ready object can be used as a context manager. On ``__enter__``,
        the ``inc()`` function is called. On ``__exit__``, the ``dec()``
        function is called.
        This uses the default Synapse global thread lock by default.
    '''
    def __init__(self, size, valu=0, lock=None):

        if size < 1:
            raise ValueError('size must be greater than 1')

        if lock is None:
            lock = s_glob.lock

        self.lock = lock
        self.valu = valu
        self.size = size
        self.evnt = threading.Event()

        self._maySetEvent()

    def _maySetEvent(self):
        '''
        Check if the counter if >= to size and if so, set the event if
        not already set. Otherwise, clears the event.
        '''
        if self.valu >= self.size and not self.evnt.is_set():
            self.evnt.set()
            return

        if self.evnt.is_set():
            self.evnt.clear()

    def wait(self, timeout=None):
        '''
        Wait for the

        Args:
            timeout (float): Number of seconds to wait for the event to occur.

        Examples:
            Wait for the event to be set and then perform some action:

                ready.wait():
                doStuff()

        Notes:
            If ``wait()`` is called in a loop with a timeout, it is possible
            that a caller may miss the event being set if another thread
            causes the event to be cleared.

        Returns:
            bool: True if the event was set, False if the timeout expired
            without the event being set.
        '''
        return self.evnt.wait(timeout=timeout)

    def inc(self, valu=1):
        '''
        Increment the counter and possibly trigger the event to be set.

        Args:
            valu (int): Value too increment the counter by.

        Notes:
            If the event has already been set, this will cause the event
            to be cleared.

        Returns:
            None
        '''
        with self.lock:
            self.valu += valu
            self._maySetEvent()

    def dec(self, valu=1):
        '''
        Decrement the counter and possibly trigger the event to be set.

        Args:
            valu (int): Value too increment the counter by.

        Notes:
            If the event has already been set, this will cause the event
            to be cleared.

        Returns:
            None
        '''
        with self.lock:
            self.valu -= valu
            self._maySetEvent()

    def __enter__(self):
        self.inc()

    def __exit__(self, exc, cls, tb):
        self.dec()

class Counter:
    '''
    The Counter class facilitates atomic counter incrementing/decrementing.

    Args:
        valu (int): Value to start the counter at.
        lock (threading.Lock): The lock used to protect the counter value.

    Notes:
        This uses the default Synapse global thread lock by default.
    '''
    def __init__(self, valu=0, lock=None):
        if lock is None:
            lock = s_glob.lock
        self._lock = lock
        self._valu = valu

    def inc(self, valu=1):
        '''
        Atomically increment the counter and return the new value.

        Args:
            valu (int): Value too increment the counter by.

        Notes:
            The valu passed to inc may be an negative integer in order to decrement the counter value.

        Returns:
            int: The new value of the counter after the increment operation has been performed.
        '''
        with self._lock:
            self._valu += valu
            return self._valu

    def valu(self):
        '''
        Get the current counter valu

        Returns:
            int: The current counter value
        '''
        with self._lock:
            return self._valu

    def set(self, valu=0):
        '''
        Resets the counter to a value.

        Args:
            valu (int): Value to set the counter too.

        Returns:
            int: The current counter value after setting it.
        '''
        with self._lock:
            self._valu = valu
            return self._valu
