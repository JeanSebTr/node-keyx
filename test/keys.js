var Key = require('keyx/key');
var dss = require('keyx/dss');

var assert = require('assert');
var bigint = require('bigint');
var Buffers = require('buffers');

exports.createKey = function () {
    assert.eql(
        new Key('test', 'dss').data,
        new Buffer('test', 'base64')
    );
    
    assert.eql(
        new Key('test', 'dss-base64').data,
        new Buffer('test', 'base64')
    );
    
    assert.eql(
        new Key('abcdef', 'dss-hex').data,
        new Buffer('abcdef', 'hex')
    );
};

exports.packParseKey = function () {
    var pubkey = dss.generate();
    var vars = [ pubkey.p, pubkey.q, pubkey.g, pubkey.y ];
    var data = Buffers(vars.map(function (x) {
        return x.toBuffer('mpint')
    })).slice();
    
    var key = Key.pack('dss', vars);
    assert.eql(key.data, data);
    
    assert.eql(key.toString(), data.toString('base64'));
    
    assert.throws(function () {
        key.format('ssh2');
    });
    
    var ssh2 = key.format('ssh2', 'private');
    var kssh2 = Key.parse(ssh2);
    assert.eql(key.data, kssh2.data);
    
    var openssh = key.format('openssh', 'moo@moo.com');
    var kopenssh = Key.parse(openssh);
    assert.eql(key.data, kopenssh.data);
};
