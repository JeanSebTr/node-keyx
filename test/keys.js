var keyx = require('keyx');
var dss = require('keyx/dss');

var assert = require('assert');
var bigint = require('bigint');
var Buffers = require('buffers');

exports.packParseKey = function () {
    var keypair = keyx.generate('dss');
    
    var ssh2 = {
        priv : keypair.key('private').format('ssh2'),
        pub : keypair.key('public').format('ssh2'),
    };
    
    assert.eql(
        keypair.key('private').data,
        keyx.parse(ssh2.priv).data
    );
    
    assert.eql(
        keypair.key('public').data,
        keyx.parse(ssh2.pub).data
    );
    
    var openssh = {
        priv : keypair.key('private').format('openssh'),
        pub : keypair.key('public').format('openssh'),
    };
    
    assert.eql(
        keypair.key('private').data,
        keyx.parse(openssh.priv).data
    );
    
    assert.eql(
        keypair.key('public').data,
        keyx.parse(openssh.pub).data
    );
};
