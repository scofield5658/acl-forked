module.exports = require('./acl.js');

module.exports.__defineGetter__('memoryBackend', () => require('./memory-backend.js'));

module.exports.__defineGetter__('mongodbBackend', () => require('./mongodb-backend.js'));
