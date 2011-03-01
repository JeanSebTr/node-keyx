keyx
====

Algorithms, parsers, and file formats for public key cryptography key exchanges.

Presently supports [DSS](http://www.itl.nist.gov/fipspubs/fip186.htm)
with [Diffie-Hellman](http://tools.ietf.org/html/rfc4253#section-8)
challenge/response.

examples/generate.js

    var keyx = require('keyx');
    var keypair = keyx.generate('dss');
    console.log(keypair.key('public').format('ssh2'));
***
    $ node examples/generate.js
    -----BEGIN DSA PUBLIC KEY-----
    AAAAB3NzaC1kc3MAAABJAKvQMeAdlpxSvFwEE1AvYeFqs1lPmRVHOzqnn3aiBgbz
    u2cLuSKG0bq2aJdgJcQx62jICLsUR/3Luuph48ptCpH1d/R3zP3AtQAAABUA6Au9
    yHZH88OCkC0vWNJ1Szm8qKsAAABITXMjWzv6ppfu+IKjFoJcr8rWQdsAiklvXVW6
    Mzxs/i5gBrSR5y8vUMfr+TE04fe5C/xR+qBXA4cQawS8vZOMiLc8D0uM5AxoAAAA
    SQCGoqNgw55bW7HrMy7brjGyo6SrtYJvRwM/v9zhBLTdxpA00gg9eeS8xUj36pNW
    NoMRnZZxc4BZjToccrbQvMv6B1zL2jZWfe4=
    -----END DSA PUBLIC KEY-----
