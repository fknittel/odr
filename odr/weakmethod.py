# vim:set encoding=utf-8 ft=python ts=8 sw=4 sts=4 et cindent:

# weakmethod.py - Provides weakly referenced proxies for bound methods.
#
# Copyright © 2010 Fabian Knittel <fabian.knittel@avona.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import weakref


class WeakBoundMethod(object):
    """Used to create a proxy method of a bound method, which weakly references
    the method's binding instance.


    Assuming the following simple class:

        >>> class Example(object):
        ...     def print_num(self, a_number):
        ...         print "%d" % a_number

    We can create an example instance and create a weak reference to the bound
    print_num method:

        >>> e = Example()
        >>> wmeth = WeakBoundMethod(e.print_num)

    The proxy method works as expected:

        >>> wmeth(5)
        5

    It holds no strong reference to e, so deleting e will invalidate the proxy
    method:

        >>> del e
        >>> wmeth(5)
        Traceback (most recent call last):
            ...
        ReferenceError

    The exception can be suppressed by setting ignore_emptiness to True:

        >>> e = Example()
        >>> wmeth = WeakBoundMethod(e.print_num, ignore_emptiness=True)
        >>> wmeth(5)
        5
        >>> del e
        >>> wmeth(5)
    """

    def __init__(self, bound_method, ignore_emptiness=False):
        """
        @param bound_method: The bound method to wrap around.
        @param ignore_emptiness: Boolean indicating whether a method call on a
                collected object should be ignored or raise a ReferenceError.
                Defaults to False.
        """
        self._free_method = bound_method.im_func
        self._weak_instance = weakref.ref(bound_method.im_self)
        self._ignore_emptiness = ignore_emptiness

    def __call__(self, *args, **kwargs):
        """
        @raises ReferenceError: When the weak reference refers to an object
                that has been collected, unless ignore_emptiness is True.
        """
        instance = self._weak_instance()
        if instance is None:
            if self._ignore_emptiness:
                # Do nothing and simply return.
                return
            raise ReferenceError
        return self._free_method(instance, *args, **kwargs)

    def __repr__(self):
        return "<%s wrapping %s and %s>" % (self.__class__,
                repr(self._weak_instance()), repr(self._free_method))

if __name__ == '__main__':
    import doctest
    doctest.testmod()
