var keyx = require('keyx');
var keypair = keyx.generate('dss');
console.log(keypair.key('public').format('ssh2'));
