var exports = module.exports = function (keys) {
    if (!keys.pub) throw new Error('Public key not specified');
    if (!keys.priv) throw new Error('Private key not specified');
    
    var pub = exports.parse(keys.pub);
    if (!pub) throw new Error('Failed to parse public key');
    if (!pub.keyType) pub.keyType = 'public';
    
    var priv = exports.parse(keys.priv);
    if (!priv) throw new Error('Failed to parse private key');
    if (!priv.keyType) pub.keyType = 'private';
    
    if (pub.algorithm !== priv.algorithm) {
        throw new Error(
            'public and private algorithms '
            + [ pub.algorithm, priv.algorithm ]
                .map(String).map(JSON.stringify).join(' and ')
            + ' disagree'
        );
    }
    
    if (!algos[pub.algorithm]) {
        throw new Error('Unsupported key type ' + pub.algorithm.toString());
    }
    
    return algos[pub.algorithm]({
        pub : new Buffer(pub.data, 'base64'),
        priv : new Buffer(priv.data, 'base64'),
    });
};

var algos = exports.algorithms = {
    dss : require('./dss'),
};

exports.generate = function (algo) {
    if (!algos[algo]) throw new Error('Unsupported key type ' + algo);
    return algos[algo].generate();
};

exports.parse = function (contents) {
    var body = contents.toString();
    
    var ssh2 = body.match(/^-----BEGIN (\S+) (PRIVATE|PUBLIC) KEY-----\n/);
    if (ssh2) {
        var algo = ssh2[1].toLowerCase();
        if (algo === 'dsa') algo = 'dss';
        
        return {
            algorithm : algo,
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
        var algo = openssh[1].toLowerCase();
        if (algo === 'dsa') algo = 'dss';
        
        return {
            algorithm : openssh[1],
            keyType : undefined,
            data : openssh[2],
        };
    }
    
    return undefined;
};
