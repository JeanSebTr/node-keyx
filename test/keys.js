var keyx = require('keyx');
var dss = require('keyx/dss');

var assert = require('assert');
var bigint = require('bigint');
var Buffers = require('buffers');

exports.createKey = function () {
    assert.eql(
        new keyx('test', 'dss').data,
        new Buffer('test', 'base64')
    );
    
    assert.eql(
        new keyx('test', 'dss-base64').data,
        new Buffer('test', 'base64')
    );
    
    assert.eql(
        new keyx('abcdef', 'dss-hex').data,
        new Buffer('abcdef', 'hex')
    );
};

exports.packParseKey = function () {
    var keypair = dss.generate();
    var pubkey = keypair.data('public');
    var privkey = keypair.data('private');
    
    var fields = keypair.fields;
    
    var vars = [ fields.p, fields.q, fields.g, fields.y ];
    var pubdata = Buffers(vars.map(function (x) {
        return x.toBuffer('mpint')
    })).slice();
    
    var key = keyx.pack('dss', vars);
    assert.eql(key.data, pubdata);
    
    assert.eql(key.toString(), pubdata.toString('base64'));
    
    assert.throws(function () {
        key.format('ssh2');
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
