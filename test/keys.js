var keyx = require('keyx');
var dss = require('keyx/dss');

var assert = require('assert');
var bigint = require('bigint');
var Buffers = require('buffers');

exports.packParseKey = function () {
    var keypair = keyx.generate('dss');
    
    assert.throws(function () {
        keypair.format('ssh2');
    });
    
    var ssh2 = key.format('ssh2', 'private');
    var kssh2 = keyx.parse(ssh2);
    assert.eql(
        key.data,
        kssh2.data
    );
    
    var openssh = key.format('openssh', 'moo@moo.com');
    var kopenssh = keyx.parse(openssh);
    assert.eql(key.data, kopenssh.data);
};
