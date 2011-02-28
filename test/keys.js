var assert = require('assert');
var Key = require('keyx/key');

exports.create = function () {
    assert.eql(
        new Key('test', 'dss').data,
        new Buffer('test', 'base64')
    );
};
