const _ = require('lodash'),
  util = require('util'),
  bluebird = require('bluebird'),
  contract = require('./contract');

contract.debug = true;

const Acl = function (backend, logger, options) {
  contract(arguments)
    .params('object')
    .params('object', 'object')
    .params('object', 'object', 'object')
    .end();

  options = _.extend({
    buckets: {
      meta: 'meta',
      parents: 'parents',
      permissions: 'permissions',
      resources: 'resources',
      roles: 'roles',
      users: 'users',
    },
  }, options);

  this.logger = logger;
  this.backend = backend;
  this.options = options;

  // Promisify async methods
  backend.endAsync = bluebird.promisify(backend.end);
  backend.getAsync = bluebird.promisify(backend.get);
  backend.cleanAsync = bluebird.promisify(backend.clean);
  backend.unionAsync = bluebird.promisify(backend.union);
  if (backend.unions) {
    backend.unionsAsync = bluebird.promisify(backend.unions);
  }
};

/**
  addUserRoles( userId, roles, function(err) )

  Adds roles to a given user id.

  @param {String|Number} User id.
  @param {String|Array} Role(s) to add to the user id.
  @param {Function} Callback called when finished.
  @return {Promise} Promise resolved when finished
*/
Acl.prototype.addUserRoles = function (userId, roles, cb) {
  contract(arguments)
    .params('string|number', 'string|array', 'function')
    .params('string|number', 'string|array')
    .end();

  const transaction = this.backend.begin();
  this.backend.add(transaction, this.options.buckets.meta, 'users', userId);
  this.backend.add(transaction, this.options.buckets.users, userId, roles);

  if (Array.isArray(roles)) {
    const that = this;

    roles.forEach((role) => {
      that.backend.add(transaction, that.options.buckets.roles, role, userId);
    });
  } else {
    this.backend.add(transaction, this.options.buckets.roles, roles, userId);
  }

  return this.backend.endAsync(transaction).nodeify(cb);
};

/**
  removeUserRoles( userId, roles, function(err) )

  Remove roles from a given user.

  @param {String|Number} User id.
  @param {String|Array} Role(s) to remove to the user id.
  @param {Function} Callback called when finished.
  @return {Promise} Promise resolved when finished
*/
Acl.prototype.removeUserRoles = function (userId, roles, cb) {
  contract(arguments)
    .params('string|number', 'string|array', 'function')
    .params('string|number', 'string|array')
    .end();

  const transaction = this.backend.begin();
  this.backend.remove(transaction, this.options.buckets.users, userId, roles);

  if (Array.isArray(roles)) {
    const that = this;

    roles.forEach((role) => {
      that.backend.remove(transaction, that.options.buckets.roles, role, userId);
    });
  } else {
    this.backend.remove(transaction, this.options.buckets.roles, roles, userId);
  }

  return this.backend.endAsync(transaction).nodeify(cb);
};

/**
  userRoles( userId, function(err, roles) )

  Return all the roles from a given user.

  @param {String|Number} User id.
  @param {Function} Callback called when finished.
  @return {Promise} Promise resolved with an array of user roles
*/
Acl.prototype.userRoles = function (userId, cb) {
  return this.backend.getAsync(this.options.buckets.users, userId).nodeify(cb);
};

/**
    roleUsers( roleName, function(err, users) )

    Return all users who has a given role.
    @param {String|Number} rolename.
    @param {Function} Callback called when finished.
    @return {Promise} Promise resolved with an array of users
 */
Acl.prototype.roleUsers = function (roleName, cb) {
  return this.backend.getAsync(this.options.buckets.roles, roleName).nodeify(cb);
};

/**
  hasRole( userId, rolename, function(err, is_in_role) )

  Return boolean whether user is in the role

  @param {String|Number} User id.
  @param {String|Number} rolename.
  @param {Function} Callback called when finished.
  @return {Promise} Promise resolved with boolean of whether user is in role
*/
Acl.prototype.hasRole = function (userId, rolename, cb) {
  return this.userRoles(userId).then((roles) => roles.indexOf(rolename) !== -1).nodeify(cb);
};

/**
  addRoleParents( role, parents, function(err) )

  Adds a parent or parent list to role.

  @param {String} Child role.
  @param {String|Array} Parent role(s) to be added.
  @param {Function} Callback called when finished.
  @return {Promise} Promise resolved when finished
*/
Acl.prototype.addRoleParents = function (role, parents, cb) {
  contract(arguments)
    .params('string|number', 'string|array', 'function')
    .params('string|number', 'string|array')
    .end();

  const transaction = this.backend.begin();
  this.backend.add(transaction, this.options.buckets.meta, 'roles', role);
  this.backend.add(transaction, this.options.buckets.parents, role, parents);
  return this.backend.endAsync(transaction).nodeify(cb);
};

/**
  removeRoleParents( role, parents, function(err) )

  Removes a parent or parent list from role.

  If `parents` is not specified, removes all parents.

  @param {String} Child role.
  @param {String|Array} Parent role(s) to be removed [optional].
  @param {Function} Callback called when finished [optional].
  @return {Promise} Promise resolved when finished.
*/
Acl.prototype.removeRoleParents = function (role, parents, cb) {
  contract(arguments)
    .params('string', 'string|array', 'function')
    .params('string', 'string|array')
    .params('string', 'function')
    .params('string')
    .end();

  if (!cb && _.isFunction(parents)) {
    cb = parents;
    parents = null;
  }

  const transaction = this.backend.begin();
  if (parents) {
    this.backend.remove(transaction, this.options.buckets.parents, role, parents);
  } else {
    this.backend.del(transaction, this.options.buckets.parents, role);
  }
  return this.backend.endAsync(transaction).nodeify(cb);
};

/**
  removeRole( role, function(err) )

  Removes a role from the system.

  @param {String} Role to be removed
  @param {Function} Callback called when finished.
*/
Acl.prototype.removeRole = function (role, cb) {
  contract(arguments)
    .params('string', 'function')
    .params('string').end();

  const that = this;
  // Note that this is not fully transactional.
  return this.backend.getAsync(this.options.buckets.resources, role).then((resources) => {
    const transaction = that.backend.begin();

    resources.forEach((resource) => {
      const bucket = allowsBucket(resource);
      that.backend.del(transaction, bucket, role);
    });

    that.backend.del(transaction, that.options.buckets.resources, role);
    that.backend.del(transaction, that.options.buckets.parents, role);
    that.backend.del(transaction, that.options.buckets.roles, role);
    that.backend.remove(transaction, that.options.buckets.meta, 'roles', role);

    // `users` collection keeps the removed role
    // because we don't know what users have `role` assigned.
    return that.backend.endAsync(transaction);
  }).nodeify(cb);
};

/**
  removeResource( resource, function(err) )

  Removes a resource from the system

  @param {String} Resource to be removed
  @param {Function} Callback called when finished.
  @return {Promise} Promise resolved when finished
*/
Acl.prototype.removeResource = function (resource, cb) {
  contract(arguments)
    .params('string', 'function')
    .params('string')
    .end();

  const that = this;
  return this.backend.getAsync(this.options.buckets.meta, 'roles').then((roles) => {
    const transaction = that.backend.begin();
    that.backend.del(transaction, allowsBucket(resource), roles);
    roles.forEach((role) => {
      that.backend.remove(transaction, that.options.buckets.resources, role, resource);
    });
    return that.backend.endAsync(transaction);
  }).nodeify(cb);
};

/**
  allow( roles, resources, permissions, function(err) )

  Adds the given permissions to the given roles over the given resources.

  @param {String|Array} role(s) to add permissions to.
  @param {String|Array} resource(s) to add permisisons to.
  @param {String|Array} permission(s) to add to the roles over the resources.
  @param {Function} Callback called when finished.

  allow( permissionsArray, function(err) )

  @param {Array} Array with objects expressing what permissions to give.

  [{roles:{String|Array}, allows:[{resources:{String|Array}, permissions:{String|Array}]]

  @param {Function} Callback called when finished.
  @return {Promise} Promise resolved when finished
*/
Acl.prototype.allow = function (roles, resources, permissions, cb) {
  contract(arguments)
    .params('string|array', 'string|array', 'string|array', 'function')
    .params('string|array', 'string|array', 'string|array')
    .params('array', 'function')
    .params('array')
    .end();

  if ((arguments.length === 1)
    || ((arguments.length === 2) && _.isObject(roles) && _.isFunction(resources))) {
    return this._allowEx(roles).nodeify(resources);
  }
  const that = this;

  roles = makeArray(roles);
  resources = makeArray(resources);

  const transaction = that.backend.begin();

  that.backend.add(transaction, that.options.buckets.meta, 'roles', roles);

  resources.forEach((resource) => {
    roles.forEach((role) => {
      that.backend.add(transaction, allowsBucket(resource), role, permissions);
    });
  });

  roles.forEach((role) => {
    that.backend.add(transaction, that.options.buckets.resources, role, resources);
  });

  return that.backend.endAsync(transaction).nodeify(cb);
};

Acl.prototype.enableRole = function (roles, status = false, cb) {
  contract(arguments)
    .params('string|array', 'boolean', 'function')
    .params('string|array', 'boolean')
    .end();

  const that = this;

  roles = makeArray(roles);

  const transaction = that.backend.begin();

  if (status) {
    that.backend.add(transaction, that.options.buckets.meta, 'roles', roles);
  } else {
    that.backend.remove(transaction, that.options.buckets.meta, 'roles', roles);
  }

  return that.backend.endAsync(transaction).nodeify(cb);
};

Acl.prototype.checkRole = function (roles, cb) {
  contract(arguments)
    .params('array', 'function')
    .params('array')
    .end();

  const that = this;

  roles = makeArray(roles);

  return this.backend.getAsync(this.options.buckets.meta, 'roles').then((realRoles) => {
    const result = {};
    roles.forEach((role) => {
      result[role] = realRoles.includes(role);
    });
    return result;
  }).nodeify(cb);
};


Acl.prototype.removeAllow = function (roles, resources, permissions, cb) {
  contract(arguments)
    .params('string|array', 'string|array', 'string|array', 'function')
    .params('string|array', 'string|array', 'string|array')
    .params('array', 'function')
    .params('array')
    .end();

  if ((arguments.length === 1)
    || ((arguments.length === 2) && _.isObject(roles) && _.isFunction(resources))) {
    return this._removeEx(roles).nodeify(resources);
  }

  resources = makeArray(resources);
  if (cb || (permissions && !_.isFunction(permissions))) {
    permissions = makeArray(permissions);
  } else {
    cb = permissions;
    permissions = null;
  }

  return this.removePermissions(roles, resources, permissions, cb);
};

/**
  removePermissions( role, resources, permissions)

  Remove permissions from the given roles owned by the given role.

  Note: we loose atomicity when removing empty role_resources.

  @param {String}
  @param {String|Array}
  @param {String|Array}
*/
Acl.prototype.removePermissions = function (role, resources, permissions, cb) {
  const that = this;

  const transaction = that.backend.begin();
  resources.forEach((resource) => {
    const bucket = allowsBucket(resource);
    if (permissions) {
      that.backend.remove(transaction, bucket, role, permissions);
    } else {
      that.backend.del(transaction, bucket, role);
      that.backend.remove(transaction, that.options.buckets.resources, role, resource);
    }
  });

  // Remove resource from role if no rights for that role exists.
  // Not fully atomic...
  return that.backend.endAsync(transaction).then(() => {
    const transaction = that.backend.begin();
    return bluebird.all(resources.map((resource) => {
      const bucket = allowsBucket(resource);
      return that.backend.getAsync(bucket, role).then((permissions) => {
        if (permissions.length === 0) {
          that.backend.remove(transaction, that.options.buckets.resources, role, resource);
        }
      });
    })).then(() => that.backend.endAsync(transaction));
  }).nodeify(cb);
};

/**
  allowedPermissions( userId, resources, function(err, obj) )

  Returns all the allowable permissions a given user have to
  access the given resources.

  It returns an array of objects where every object maps a
  resource name to a list of permissions for that resource.

  @param {String|Number} User id.
  @param {String|Array} resource(s) to ask permissions for.
  @param {Function} Callback called when finished.
*/
Acl.prototype.allowedPermissions = function (userId, resources, cb) {
  if (!userId) { return cb(null, {}); }

  contract(arguments)
    .params('string|number', 'string|array', 'function')
    .params('string|number', 'string|array')
    .end();

  if (this.backend.unionsAsync) {
    return this.optimizedAllowedPermissions(userId, resources, cb);
  }

  const that = this;
  resources = makeArray(resources);

  return that.userRoles(userId).then((roles) => {
    const result = {};
    return bluebird.all(resources.map((resource) => that._resourcePermissions(roles, resource)
      .then((permissions) => {
        result[resource] = permissions;
      })))
      .then(() => result);
  }).nodeify(cb);
};

/**
  optimizedAllowedPermissions( userId, resources, function(err, obj) )

  Returns all the allowable permissions a given user have to
  access the given resources.

  It returns a map of resource name to a list of permissions for that resource.

  This is the same as allowedPermissions, it just takes advantage of the unions
  function if available to reduce the number of backend queries.

  @param {String|Number} User id.
  @param {String|Array} resource(s) to ask permissions for.
  @param {Function} Callback called when finished.
*/
Acl.prototype.optimizedAllowedPermissions = function (userId, resources, cb) {
  if (!userId) {
    return cb(null, {});
  }

  contract(arguments)
    .params('string|number', 'string|array', 'function|undefined')
    .params('string|number', 'string|array')
    .end();

  resources = makeArray(resources);
  const self = this;

  return this._allUserRoles(userId).then((roles) => {
    const buckets = resources.map(allowsBucket);
    if (roles.length === 0) {
      const emptyResult = {};
      buckets.forEach((bucket) => {
        emptyResult[bucket] = [];
      });
      return bluebird.resolve(emptyResult);
    }

    return self.backend.unionsAsync(buckets, roles);
  }).then((response) => {
    const result = {};
    Object.keys(response).forEach((bucket) => {
      result[keyFromAllowsBucket(bucket)] = response[bucket];
    });

    return result;
  }).nodeify(cb);
};

/**
  isAllowed( userId, resource, permissions, function(err, allowed) )

  Checks if the given user is allowed to access the resource for the given
  permissions (note: it must fulfill all the permissions).

  @param {String|Number} User id.
  @param {String|Array} resource(s) to ask permissions for.
  @param {String|Array} asked permissions.
  @param {Function} Callback called wish the result.
*/
Acl.prototype.isAllowed = function (userId, resource, permissions, cb) {
  contract(arguments)
    .params('string|number', 'string', 'string|array', 'function')
    .params('string|number', 'string', 'string|array')
    .end();

  const that = this;

  return this.backend.getAsync(this.options.buckets.users, userId).then((roles) => {
    if (roles.length) {
      return that.areAnyRolesAllowed(roles, resource, permissions);
    }
    return false;
  }).nodeify(cb);
};

/**
  areAnyRolesAllowed( roles, resource, permissions, function(err, allowed) )

  Returns true if any of the given roles have the right permissions.

  @param {String|Array} Role(s) to check the permissions for.
  @param {String} resource(s) to ask permissions for.
  @param {String|Array} asked permissions.
  @param {Function} Callback called with the result.
*/
Acl.prototype.areAnyRolesAllowed = function (roles, resource, permissions, cb) {
  contract(arguments)
    .params('string|array', 'string', 'string|array', 'function')
    .params('string|array', 'string', 'string|array')
    .end();

  roles = makeArray(roles);
  permissions = makeArray(permissions);

  if (roles.length === 0) {
    return bluebird.resolve(false).nodeify(cb);
  }
  return this._checkPermissions(roles, resource, permissions);
};

/**
  whatResources(role, function(err, {resourceName: [permissions]})

  Returns what resources a given role or roles have permissions over.

  whatResources(role, permissions, function(err, resources) )

  Returns what resources a role has the given permissions over.

  @param {String|Array} Roles
  @param {String[Array} Permissions
  @param {Function} Callback called wish the result.
*/
Acl.prototype.whatResources = function (roles, permissions, cb) {
  contract(arguments)
    .params('string|array')
    .params('string|array', 'string|array')
    .params('string|array', 'function')
    .params('string|array', 'string|array', 'function')
    .end();

  roles = makeArray(roles);
  if (_.isFunction(permissions)) {
    cb = permissions;
    permissions = undefined;
  } else if (permissions) {
    permissions = makeArray(permissions);
  }

  return this.permittedResources(roles, permissions, cb);
};

Acl.prototype.permittedResources = function (roles, permissions, cb) {
  const that = this;
  const result = _.isUndefined(permissions) ? {} : [];
  return this._rolesResources(roles).then((resources) => bluebird.all(resources.map((resource) => that._resourcePermissions(roles, resource).then((p) => {
    if (permissions) {
      const commonPermissions = _.intersection(permissions, p);
      if (commonPermissions.length > 0) {
        result.push(resource);
      }
    } else {
      result[resource] = p;
    }
  }))).then(() => result)).nodeify(cb);
};

/**
  clean ()

  Cleans all the keys with the given prefix from redis.

  Note: this operation is not reversible!.
*/
/*
Acl.prototype.clean = function(callback){
  var acl = this;
  this.redis.keys(this.prefix+'*', function(err, keys){
    if(keys.length){
      acl.redis.del(keys, function(err){
        callback(err);
      });
    }else{
      callback();
    }
  });
};
*/

/**
  Express Middleware

*/
Acl.prototype.middleware = function (numPathComponents, userId, actions) {
  contract(arguments)
    .params()
    .params('number')
    .params('number', 'string|number|function')
    .params('number', 'string|number|function', 'string|array')
    .end();

  const acl = this;

  function HttpError(errorCode, msg) {
    this.errorCode = errorCode;
    this.message = msg;
    this.name = this.constructor.name;

    Error.captureStackTrace(this, this.constructor);
    this.constructor.prototype.__proto__ = Error.prototype;
  }

  return function (req, res, next) {
    let _userId = userId,
      _actions = actions,
      resource;

    // call function to fetch userId
    if (typeof userId === 'function') {
      _userId = userId(req, res);
    }
    if (!userId) {
      if ((req.session) && (req.session.userId)) {
        _userId = req.session.userId;
      } else if ((req.user) && (req.user.id)) {
        _userId = req.user.id;
      } else {
        next(new HttpError(401, 'User not authenticated'));
        return;
      }
    }

    // Issue #80 - Additional check
    if (!_userId) {
      next(new HttpError(401, 'User not authenticated'));
      return;
    }

    const url = req.originalUrl.split('?')[0];
    if (!numPathComponents) {
      resource = url;
    } else {
      resource = url.split('/').slice(0, numPathComponents + 1).join('/');
    }

    if (!_actions) {
      _actions = req.method.toLowerCase();
    }

    acl.logger ? acl.logger.debug(`Requesting ${_actions} on ${resource} by user ${_userId}`) : null;

    acl.isAllowed(_userId, resource, _actions, (err, allowed) => {
      if (err) {
        next(new Error('Error checking permissions to access resource'));
      } else if (allowed === false) {
        if (acl.logger) {
          acl.logger.debug(`Not allowed ${_actions} on ${resource} by user ${_userId}`);
          acl.allowedPermissions(_userId, resource, (err, obj) => {
            acl.logger.debug(`Allowed permissions: ${util.inspect(obj)}`);
          });
        }
        next(new HttpError(403, 'Insufficient permissions to access resource'));
      } else {
        acl.logger ? acl.logger.debug(`Allowed ${_actions} on ${resource} by user ${_userId}`) : null;
        next();
      }
    });
  };
};

/**
  Error handler for the Express middleware

  @param {String} [contentType] (html|json) defaults to plain text
*/
Acl.prototype.middleware.errorHandler = function (contentType) {
  let method = 'end';

  if (contentType) {
    switch (contentType) {
    case 'json': method = 'json'; break;
    case 'html': method = 'send'; break;
    default: break;
    }
  }

  return function (err, req, res, next) {
    if (err.name !== 'HttpError' || !err.errorCode) return next(err);
    return res.status(err.errorCode)[method](err.message);
  };
};


//-----------------------------------------------------------------------------
//
// Private methods
//
//-----------------------------------------------------------------------------

//
// Same as allow but accepts a more compact input.
//
Acl.prototype._allowEx = function (objs) {
  const that = this;
  objs = makeArray(objs);

  const demuxed = [];
  objs.forEach((obj) => {
    const roles = obj.roles;
    obj.allows.forEach((allow) => {
      demuxed.push({
        roles,
        resources: allow.resources,
        permissions: allow.permissions,
      });
    });
  });

  return bluebird.reduce(demuxed, (values, obj) => that.allow(obj.roles, obj.resources, obj.permissions), null);
};

Acl.prototype._removeEx = function (objs) {
  const that = this;
  objs = makeArray(objs);

  const demuxed = [];
  objs.forEach((obj) => {
    const roles = obj.roles;
    obj.allows.forEach((allow) => {
      demuxed.push({
        roles,
        resources: allow.resources,
        permissions: allow.permissions,
      });
    });
  });

  return bluebird.reduce(demuxed, (values, obj) => that.removeAllow(obj.roles, obj.resources, obj.permissions), null);
};

//
// Returns the parents of the given roles
//
Acl.prototype._rolesParents = function (roles) {
  return this.backend.unionAsync(this.options.buckets.parents, roles);
};

//
// Return all roles in the hierarchy including the given roles.
//
/*
Acl.prototype._allRoles = function(roleNames, cb){
  var that = this, roles;

  that._rolesParents(roleNames, function(err, parents){
    roles = _.union(roleNames, parents);
    async.whilst(
      function (){
        return parents.length >0;
      },
      function (cb) {
        that._rolesParents(parents, function(err, result){
          if(!err){
            roles = _.union(roles, parents);
            parents = result;
          }
          cb(err);
        });
      },
      function(err){
        cb(err, roles);
      }
    );
  });
};
*/
//
// Return all roles in the hierarchy including the given roles.
//
Acl.prototype._allRoles = function (roleNames) {
  const that = this;

  return this._rolesParents(roleNames).then((parents) => {
    if (parents.length > 0) {
      return that._allRoles(parents).then((parentRoles) => _.union(roleNames, parentRoles));
    }
    return roleNames;
  });
};

//
// Return all roles in the hierarchy of the given user.
//
Acl.prototype._allUserRoles = function (userId) {
  const that = this;

  return this.userRoles(userId).then((roles) => {
    if (roles && roles.length > 0) {
      return that._allRoles(roles);
    }
    return [];
  });
};

//
// Returns an array with resources for the given roles.
//
Acl.prototype._rolesResources = function (roles) {
  const that = this;
  roles = makeArray(roles);

  return this._allRoles(roles).then((allRoles) => {
    let result = [];

    // check if bluebird.map simplifies this code
    return bluebird.all(allRoles.map((role) => that.backend.getAsync(that.options.buckets.resources, role).then((resources) => {
      result = result.concat(resources);
    }))).then(() => result);
  });
};

//
// Returns the permissions for the given resource and set of roles
//
Acl.prototype._resourcePermissions = function (roles, resource) {
  const that = this;

  if (roles.length === 0) {
    return bluebird.resolve([]);
  }
  return this.backend.unionAsync(allowsBucket(resource), roles).then((resourcePermissions) => that._rolesParents(roles).then((parents) => {
    if (parents && parents.length) {
      return that._resourcePermissions(parents, resource).then((morePermissions) => _.union(resourcePermissions, morePermissions));
    }
    return resourcePermissions;
  }));
};

//
// NOTE: This function will not handle circular dependencies and result in a crash.
//
Acl.prototype._checkPermissions = function (roles, resource, permissions) {
  const that = this;

  return new Promise((resolve) => {
    that.backend.getAsync(that.options.buckets.meta, 'roles').then((realRoles) => {
      const result = {};
      roles.forEach((role) => {
        result[role] = realRoles.includes(role);
      });
      return result;
    }).then((result) => {
      const filterRoles = roles.filter(role => result[role]);
      that.backend.unionAsync(allowsBucket(resource), filterRoles).then((resourcePermissions) => {
        if (resourcePermissions.indexOf('*') !== -1) {
          resolve(true);
        }
        permissions = permissions.filter((p) => resourcePermissions.indexOf(p) === -1);

        if (permissions.length === 0) {
          resolve(true);
        }
        return that.backend.unionAsync(that.options.buckets.parents, filterRoles).then((parents) => {
          if (parents && parents.length) {
            resolve(that._checkPermissions(parents, resource, permissions));
          }
          resolve(false);
        });
      });
    });
  });
};

//-----------------------------------------------------------------------------
//
// Helpers
//
//-----------------------------------------------------------------------------

function makeArray(arr) {
  return Array.isArray(arr) ? arr : [arr];
}

function allowsBucket(role) {
  return `allows_${role}`;
}

function keyFromAllowsBucket(str) {
  return str.replace(/^allows_/, '');
}


// -----------------------------------------------------------------------------------


exports = module.exports = Acl;
