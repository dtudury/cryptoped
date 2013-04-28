cryptoped
=========

highly optimized specific use crypto library

I wrote this (because it was fun and) for a password generator.
crypto-js (https://code.google.com/p/crypto-js/) is awesome but
the pbkdf2 seems to get exponentially slower with more iterations.
This library does fast pbkdf2, the algorithms are more-or-less
straight off of wikipedia.

You can test the speed for yourself at:
http://cryptoped.jit.su/

and the github page:
https://npmjs.org/package/cryptoped