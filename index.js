module.exports = require('./lib/acl.js');

module.exports.__defineGetter__('memoryBackend', () => require('./lib/memory-backend.js'));
module.exports.__defineGetter__('mongodbBackend', () => require('./lib/mongodb-backend.js'));
