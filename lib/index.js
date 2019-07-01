module.exports = require('./acl.js');

module.exports.__defineGetter__('memoryBackend', function(){
  return require('./memory-backend.js');
});

module.exports.__defineGetter__('mongodbBackend', function(){
  return require('./mongodb-backend.js');
});
