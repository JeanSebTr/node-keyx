var exports = module.exports = function (keys) {
    if (!keys.public) throw new Error('Public key not specified');
    if (!keys.private) throw new Error('Private key not specified');
    
    var pub = exports.parse(keys.public);
    if (!pub) throw new Error('Failed to parse public key');
    
    var priv = exports.parse(keys.private);
    if (!priv) throw new Error('Failed to parse private key');
    
    if (pub.keyType != priv.keyType) throw new Error('key types disagree');
    
    if (!algos[pub.keyType]) {
        throw new Error('Unsupported key type ' + pub.keyType.toString());
    }
     
    return algos[pub.keyType]({ public : pub, private : priv });
};

var algos = exports.algorithms = {
    dss : require('./dss'),
};

exports.generate = function (algo) {
    if (!algos[algo]) throw new Error('Unsupported key type ' + algo);
    return algos[algo].generate();
};

exports.parse = function (body) {
    var ssh2 = body.match(/^-----BEGIN (\S+) (PRIVATE|PUBLIC) KEY-----\n/);
    if (ssh2) {
        return {
            algorithm : ssh2[1].toLowerCase(),
            keyType : ssh2[2].toLowerCase(),
            data : body.toString().split('\n')
                .filter(function (line) {
                    return line.match(/^\S+\s*$/)
                })
                .join('')
                .replace(/\s+/g,'')
            ,
        };
    }
    
    var openssh = body.match(/^ssh-(\S+)\s+(\S+)/);
    if (openssh) {
        return {
            algorithm : openssh[1],
            keyType : undefined,
            data : openssh[2],
        };
    }
    
    return undefined;
};
