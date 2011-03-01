var assert = require('assert');

var bigint = require('bigint');
var put = require('put');
var Hash = require('hashish');
var Buffers = require('buffers');

// Generate two primes p and q to the Digital Signature Standard (DSS)
// http://www.itl.nist.gov/fipspubs/fip186.htm appendix 2.2

var exports = module.exports = DSS;

function DSS (fields) {
    if (!(this instanceof DSS)) return new DSS(fields);
    
    this.fields = Hash.merge(fields, {
        k : function (e) { return e.powm(ref.y, ref.p) },
        f : fields.g.powm(fields.y, fields.p),
    });
}

DSS.prototype.data = function (privPub) {
    var p = (privPub || '').toUpperCase();
    
    if (p === 'PRIVATE') {
        return this.fields.x.toBuffer().toString('base64');
    }
    else if (p === 'PUBLIC') {
        var fields = this.fields;
        return Buffers(exports.fields.public.map(function (name) {
            return fields[name].toBuffer('mpint')
        })).slice();
    }
    else throw new Error('Specify "private" or "public"')
};

exports.fields = {
    public : [ 'p', 'q', 'g', 'y' ],
    private : [ 'x' ],
};

exports.generate = function () {
    var q = bigint(2).pow(159).add(1).rand(bigint(2).pow(160)).nextPrime();
    var L = 512 + 64 * Math.floor(Math.random() * 8);
    
    do {
        var X = bigint(2).pow(L-1).add(1).rand(bigint(2).pow(L));
        var c = X.mod(q.mul(2));
        var p = X.sub(c.sub(1)); // p is congruent to 1 % 2q somehow!
    } while (p.lt(bigint.pow(2, L - 1)) || p.probPrime(50) === false)
    
    assert.ok(q.gt(bigint.pow(2,159)), 'q > 2**159');
    assert.ok(q.lt(bigint.pow(2,160)), 'q < 2**160');
    assert.ok(p.gt(bigint.pow(2,L-1)), 'p > 2**(L-1)');
    assert.ok(q.lt(bigint.pow(2,L)), 'p < 2**L');
    assert.ok(q.mul(p.sub(1).div(q)).add(1).eq(p), 'q divides p - 1');
    
    do {
        var e = p.sub(1).div(q);
        var h = p.sub(2).rand().add(1);
        var g = h.powm(e, p);
    } while (g.eq(1))
    
    var x = q.sub(1).rand().add(1); // private key
    var y = g.powm(x, p); // public key
    
    return module.exports({ p : p, q : q, g : g, y : y, x : x });
};
