module.exports = function (format, keypair, kt, email) {
    if (kt === 'priv') kt = 'private';
    if (kt === 'pub') kt = 'public';
    if (kt !== 'private' && kt !== 'public') {
        throw new Error('Must specify private or public');
    }
    var data = keypair.keys[kt].toString('base64');
    
    if (format === 'ssh2') {
        
        var algo = keypair.algorithm.toUpperCase();
        if (algo === 'DSS') algo = 'DSA';
        
        var wrapped = [];
        for (var i = 0; i < data.length; i += 64) {
            wrapped.push(data.slice(i, i + 64));
        }
        
        var KT = kt.toUpperCase();
        return [
            [ '-----BEGIN', algo, KT, 'KEY-----' ].join(' '),
            wrapped.join('\n'),
            [ '-----END', algo, KT, 'KEY-----' ].join(' '),
            ''
        ].join('\n');
    }
    else if (format === 'openssh') {
        var id = 'ssh-' + keypair.algorithm;
        return [ id, data, kt || '' ].join(' ') + '\r\n';
    }
    else throw new Error('Unrecognized format ' + format.toString());
};
