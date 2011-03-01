var assert = require('assert');
var crypto = require('crypto');

var Hash = require('hashish');
var bigint = require('bigint');

var Buffers = require('buffers');
var Binary = require('binary');

var Put = require('put');
function pack (buf) {
    return Put().word32be(buf.length).put(buf).buffer();
}

var Format = require('./format');

var exports = module.exports = DSS;

function DSS (keys) {
    if (!(this instanceof DSS)) return new DSS(keys);
    
    if (!keys.public) throw new Error('Public key not specified');
    if (!keys.private) throw new Error('Private key not specified');
    
    this.algorithm = 'dss';
    this.keys = keys;
    this.fields = { x : bigint.fromBuffer(keys.private) };
    
    var buffers = Binary.parse(keys.public)
        .word32be('length.p').buffer('buffers.p', 'length.p')
        .word32be('length.q').buffer('buffers.q', 'length.q')
        .word32be('length.g').buffer('buffers.g', 'length.g')
        .word32be('length.y').buffer('buffers.y', 'length.y')
        .vars.buffers
    ;
    
    'pqgy'.split('').forEach(function (name) {
        this.fields[name] = bigint.fromBuffer(buffers[name]);
    });
    
    if (!this.valid()) throw new Error('Public and private keys disagree');
}

DSS.fromFields = function (fields) {
    var dss = Object.create(DSS.prototype);
    
    dss.algorithm = 'dss';
    dss.fields = fields;
    
    var bufs = 'pqgy'.split('').map(function (name) {
        return fields[name].toBuffer('mpint')
    });
    
    var id = pack(new Buffer('ssh-dss'));
    bufs.unshift(id);
    
    dss.keys = {
        private : fields.x.toBuffer(),
        public : Buffers(bufs).slice(),
    };
    
    if (!dss.valid()) throw new Error('Invalid fields');
    
    return dss;
}

DSS.prototype.valid = function () {
    var y = this.fields.g.powm(this.fields.x, this.fields.p);
    return y.toString() === this.fields.y.toString();
};

DSS.prototype.challenge = function (ebuf, params) {
    var e = bigint.fromBuffer(ebuf);
    var K = e.powm(this.fields.y, this.fields.p).toBuffer('mpint');
    var f = this.fields.g.powm(this.fields.y, this.fields.p).toBuffer('mpint');
    
    var K_S = pack(this.keys.public);
    
    var V_C = pack(params.client.ident);
    var V_S = pack(params.server.ident);
    var I_C = pack(params.client.kexinit);
    var I_S = pack(params.server.kexinit);
    
    var sign = crypto.createSign('DSA');
    
    [ V_C, V_S, I_C, I_S, K_S, ebuf, f, K ]
        .forEach(function (buf) { sign.update(buf) });
    
    var signed = new Buffer(sign.sign(this.keys.private, 'base64'), 'base64');
    
    return Buffers([ K_S, f.toBuffer('mpint'), signed ]).slice();
};

DSS.prototype.key = function (kt) {
    return {
        data : this.keys[kt].toString('base64'),
        format : (function (format, aux) {
            return Format(format, this, kt, aux)
        }).bind(this)
    }
};

// Generate two primes p and q to the Digital Signature Standard (DSS)
// http://www.itl.nist.gov/fipspubs/fip186.htm appendix 2.2

DSS.generate = function () {
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
    
    return DSS.fromFields({ p : p, q : q, g : g, y : y, x : x });
};
