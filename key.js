var Buffers = require('buffers');

module.exports = Key;

function Key (keyData, format) {
    if (!(this instanceof Key)) return new Key(keyData, format);
    this.algorithm = format.split('-')[0];
    
    if (typeof keyData === 'string') {
        var encoding = format && format.split('-')[1] || 'base64';
        this.data = new Buffer(keyData, encoding);
    }
    else if (Buffer.isBuffer(keyData)) {
        this.data = keyData;
    }
    else {
        throw new Error('keyData must be a string or Buffer');
    }
}

Key.pack = function (algorithm) {
    var bufs = [].slice.call(arguments, 1)
        .map(function (bigi) { return bigi.toBuffer('mpint') });
    var packed = Buffers(bufs).slice();
    return new Key(packed, algorithm);
};

Key.parse = function (body) {
    var ssh2 = body.match(/^-----BEGIN (\S+) (PRIVATE|PUBLIC) KEY-----\n/);
    if (ssh2) {
        return new Key(
            body
                .toString()
                .split('\n')
                .slice(1,-2)
                .filter(function (line) { return !line.match(/:/) })
                .join('')
                .replace(/\s+/g,'')
            , ssh2[1]
        );
    }
    
    var openssh = body.match(/^ssh-(\S+)\s+(\S+)/);
    if (openssh) {
        return new Key(openssh[2], openssh[1]);
    }
    
    return undefined;
};

Key.prototype.toString = function (encoding) {
    return this.fields
        .reduce(function (put, x) {
            return put.put(x.toBuffer('mpint'))
        }, Put().word32be(id.length).put(new Buffer(id)))
        .buffer().toString(encoding || 'base64')
    ;
};

Key.prototype.format = function (format, privOrPub, cols) {
    var fmt = (format || 'ssh2').toLowerCase();
    if (fmt === 'ssh2') {
        var p = (privOrPub || '').toUpperCase();
        if (p !== 'PRIVATE' && p !== 'PUBLIC') {
            throw new Error('Must specify private or public for ssh2');
        }
        
        var algo = this.algorithm.toUpperCase();
        
        var wrapped = [];
        for (var i = 0; i < this.data.length; i += 64) {
            wrapped.push(this.data.slice(
                i, Math.min(this.data.length, i + 64)
            ));
        }
        
        return [
            [ '-----BEGIN', algo, p, 'KEY-----' ].join(' '),
            wrapped.join('\n'),
            [ '-----END', algo, p, 'KEY-----' ].join(' '),
        ].join('\n');
    }
    else if (fmt === 'openssh') {
        var id = this.algorithm;
        if (id === 'dsa') id = 'dss';
        return [ 'ssh-' + id, this.data, email || '' ].join(' ') + '\r\n';
    }
    else throw new Error('Unrecognized format ' + format.toString());
};
