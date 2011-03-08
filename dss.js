var assert = require('assert');
var crypto = require('crypto');

var bigint = require('bigint');
var Buffers = require('buffers');
var Binary = require('binary');

var Put = require('put');
function pack (buf) {
    if (Buffer.isBuffer(buf)) {
        return Put().word32be(buf.length).put(buf).buffer();
    }
    else {
        return pack(new Buffer(buf.toString()));
    }
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
        .word32be('length.id').buffer('buffers.id', 'length.id')
        .word32be('length.p').buffer('buffers.p', 'length.p')
        .word32be('length.q').buffer('buffers.q', 'length.q')
        .word32be('length.g').buffer('buffers.g', 'length.g')
        .word32be('length.y').buffer('buffers.y', 'length.y')
        .vars.buffers
    ;
    
    if (buffers.id.toString() !== 'ssh-dss') {
        throw new Error('id != "ssh-dss"');
    }
    
    'pqgy'.split('').forEach((function (name) {
        this.fields[name] = bigint.fromBuffer(buffers[name]);
    }).bind(this));
    
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

DSS.prototype.challenge = function (kexdh, params) {
    var kexAlgo = params.choices.kex_algorithms.serverName;
    var macAlgo = params.choices.mac_algorithms_server_to_client.serverName;
    
    if (kexAlgo != 'diffie-hellman-group1-sha1') {
        throw new Error('Unsupported key exchange algorithm ' + kexAlgo);
    }
    
    var e = bigint.fromBuffer(
        Binary.parse(kexdh)
            .skip(1)
            .word32be('length')
            .buffer('e', 'length')
            .vars.e
    );
    
    assert.deepEqual(
        kexdh.slice(1), e.toBuffer('mpint'),
        'mismatch in mpint parameter e identity operation'
    );
    
    var K = e.powm(this.fields.y, this.fields.p);
    var f = this.fields.g.powm(this.fields.y, this.fields.p);
    
    function sha1 (buf) {
        var b = crypto.createHash('sha1').update(buf).digest('base64');
        return new Buffer(b, 'base64');
    }
    
    var sign = (function () {
        var p = this.fields.p;
        var x = this.fields.x;
        var g = this.fields.g;
        var q = this.fields.q;
        
        var y = this.fields.y; // public key
        
        var r = g.powm(K, p).mod(q);
        assert.ok(r.lt(q) && r.gt(0));
        
        return function sign (M) {
            if (!Buffer.isBuffer(M)) throw new Error('not a buffer');
            
            var s = K.invertm(q)
                .mul(
                    bigint.fromBuffer(sha1(M))
                    .add(x.mul(r))
                )
                .mod(q)
            ;
            assert.ok(s.lt(q) && s.gt(0));
            
            // verification that the client will do:
            var w = s.invertm(q);
            var u1 = bigint.fromBuffer(sha1(M)).mul(w).mod(q);
            var u2 = r.mul(w).mod(q);
            var v = g.powm(u1, p).mul(y.powm(u2, p)).mod(p).mod(q);
            assert.ok(v.eq(r), v + ' != ' + r);
            
            return Buffers([ r.toBuffer(), s.toBuffer() ]).slice();
        };
    }).call(this);
    
    var K_S = pack(Buffers([
        pack('ssh-dss'),
        this.fields.p.toBuffer('mpint'),
        this.fields.q.toBuffer('mpint'),
        this.fields.g.toBuffer('mpint'),
        this.fields.y.toBuffer('mpint'),
    ]).slice());
    
    var V_C = pack(params.client.ident);
    var V_S = pack(params.server.ident);
    var I_C = pack(params.client.kexinit);
    var I_S = pack(params.server.kexinit);
    
    var H = sha1(Buffers([
        V_C, V_S, I_C, I_S, K_S,
        e.toBuffer('mpint'),
        f.toBuffer('mpint'),
        K.toBuffer('mpint'),
    ]).slice());
    
    var signed = pack(Buffers([
        pack('ssh-dss'),
        pack(sign(H))
    ]).slice());
    
    console.log('-- signed --');
    console.log(signed);
    console.log(' --- ');
    
    var seqNum = 0;
    
    return {
        reply : Buffers([
            new Buffer([ 31 ]), // SSH_MSG_KEXDH_REPLY
            K_S, f.toBuffer('mpint'), signed
        ]).slice(),
        mac : function (buf) { // the mac filter to use on packets
            var b64 = crypto.createHmac(macAlgo, K.toBuffer())
                .update(Put()
                    .word32be(seqNum)
                    .put(buf)
                    .buffer()
                )
                .digest('base64')
            ;
            var b = new Buffer(b64, 'base64');
            
            seqNum = (seqNum + 1) % Math.pow(256, 4);
            return Put().word32be(b.length).put(b).buffer();
        },
    };
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
