'use strict';


// MongoDB database plugin for Impress Application Server
//
if (api.gs) {

  api.db.gs = {};
  api.db.gs.schema = {};
  api.db.drivers.gs = api.gs;

  // Load driver
  //   driverName - driver name, e.g. mongodb, mysql, pgsql, mamcached
  //   returns - driver object
  //
  api.db.gs.getDatabaseProvider = function(driverName) {
    var driver = impress.security[driverName];
    if (!driver) {
      require('./api.db.gs.' + driverName);
      driver = api.db.gs[driverName];
    }
    return driver;
  };

  // Open globalstorage database
  //
  // Example:
  //
  // open({
  //   alias: 'gs',
  //   url: 'gs://metarhia.com/',
  //   storage: 'dbAlias'
  // }, callback);
  //
  // callback after connection established
  //
  api.db.gs.open = function(database, callback) {
    api.gs.connect(database.url, function(err, clientConnection) {
      if (!err) {
        database.connection = clientConnection;
        api.db.gs.mixinDatabase(database);
      }
      callback();
    });
  };

  // Load or create collections
  //
  api.db.gs.mixinDatabase = function(database) {

  };

}