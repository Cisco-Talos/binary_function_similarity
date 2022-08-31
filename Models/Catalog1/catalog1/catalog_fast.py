# Binding the C library to python:
import ctypes
from ctypes import cdll

CATALOG1_LIB = 'libcatalog1.so'
CATALOG1_LIB_PATH = "catalog1/bin/libcatalog1.so"


class Catalog1Sign:
    """
    A class for calling the sign function from libcatalog1
    """

    def __init__(self, lib_name=CATALOG1_LIB):
        # Get the catalog1 sign function:
        self._catalog1_lib = cdll.LoadLibrary(CATALOG1_LIB_PATH)
        self._csign = self._catalog1_lib.sign
        # Return value is an integer:
        self._csign.restype = ctypes.c_int32

    def sign(self, data, num_perms):
        """
        Sign data using <num_perms> permutations.
        """
        if len(data) < 4:
            raise Exception('data must be at least of size 4 bytes.')

        arr_perms = ctypes.c_uint32 * num_perms
        # Initialize array for return value:
        # DEBUG print(arr_perms)
        s = arr_perms()
        # DEBUG print(list(s))
        res = self._csign(data, len(data), s, num_perms)
        # DEBUG print(res)
        # DEBUG print(data)
        # DEBUG print(list(s))
        if res != 0:
            raise Exception(
                'Error number: {} when calling sign()'.format(res))

        return list(s)


# Initialize one instance for this module:
c1s = Catalog1Sign(CATALOG1_LIB)


def sign(data, num_perms):
    """
    Sign over data.
    Calls the sign function from libcatalog1.so
    """
    return c1s.sign(data, num_perms)
