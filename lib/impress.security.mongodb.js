'use strict';

// MongoDB security provider for Impress Application Server
//
impress.security.mongodb = {};

// Mixin security to application instance
//
impress.security.mongodb.mixin = function(application) {

  // Create collections and indexes for security subsystem in MongoDB
  //
  application.security.createDataStructures = function(callback) {
    if (!api.db.mongodb) application.log.warning('No MongoDB drivers found');
    else {
      var securitySchema = api.definition.require('impress.security.schema');
      if (!securitySchema) {
        application.log.warning('No Impress security database schema for MongoDB loaded');
        if (callback) callback();
      } else {
        application.databases.security.generateSchema(securitySchema, function() {
          console.log('  Data changed. Bye!'.green);
          if (callback) callback();
        });
      }
    }
  };

  application.security.dropDataStructures = function(callback) {
    // Not implemented
    if (callback) callback();
  };

  application.security.emptyDataStructures = function(callback) {
    // Not implemented
    if (callback) callback();
  };

  application.security.hash = function(password, callback) {
    var saltRounds = application.config.saltRounds || 10;
    api.bcrypt.genSalt(saltRounds, function(err, salt) {
      if (err) {
        return callback(err);
      }

      api.bcrypt.hash(password, salt, function(err, password) {
        if (err) {
          return callback(err);
        }

        callback(null, password);
      });
    });
  };

  // Register user, return true/false
  //   callback(err, sid)
  //
  //   userInfo: {
  //     login,
  //     password,
  //     group,
  //   }
  //
  application.security.signUp = function(userInfo, callback) {
    var login = userInfo.login,
        password = userInfo.password;
        application.security.hash(password, function(err, hashedPassword) {
          application.databases.security.users.insert({
            login: login,
            hashedPassword: hashedPassword,
            group: userInfo.group
          }, function(err, result) {
            if (!err && result.ops.length > 0) {
              var user = new application.security.User(result.ops[0]);
              user.uid = result.ops[0]._id;
              application.users[user.uid] = user;
              var session = new application.security.Session({
                uid: user.uid,
              });
              application.security.saveSession(session, callback);
            } else {
              callback(err || new Error('User was not inserted to database'));
            }
          });
        });
  };
  // Verify user information
  //   callback(err, isSuccess)
  //
  //   userInfo: {
  //     login,
  //     password,
  //     group,
  //   }
  //
  application.security.verify = function(userInfo, callback) {
    var login = userInfo.login,
        password = userInfo.password,
        group = userInfo.group;
    application.databases.security.users.find({ login: login }).toArray(
      function(err, users) {
        if (users.length === 0) {
          return callback(new Error('Wrong login'));
        }
        api.metasync.find(users, function(user, callback) {
          api.bcrypt.compare(password, user.hashedPassword, function(err, isMatch) {
            callback(err || (isMatch && group === user.group));
          });
        }, function(user) {
          if (user === undefined) {
            return callback(new Error('Wrong password or group'));
          }
          callback(null, user._id);
        });
      });
  };

  // Checks user login, password and group
  //   callback(err, sid)
  // sessionStorageObject = object that can be used to store session data
  // userInfo = {
  //   login,
  //   password,
  //   group
  // }
  application.security.signIn = function(userInfo, callback) {
    application.security.verify(userInfo, function(err, uid) {
      if (err) {
        return callback(err);
      }
      var session = new application.security.Session({ uid: uid });
      application.security.saveSession(session, callback);
    });
  };

  application.security.signOut = function(sid, callback) {
    delete application.sessions[sid];
    application.databases.security.sessions.removeOne({ sid: sid }, function(err) {
      if (err) {
        return callback(err);
      }
      callback(null, true);
    });
  };

  application.security.saveSession = function(session, callback) {
    var sid = session.sid;
    application.sessions[sid] = session;
    application.databases.security.sessions.update({ sid: sid }, session,
      { upsert: true }, function(err) {
        if (err) {
          return callback(err);
        }
        callback(null, sid);
      });
  };

  application.security.restoreSession = function(sid, callback) {
    application.databases.security.sessions.findOne({ sid: sid },
      function(err, session) {
        if (err) {
          return callback(err);
        }
        application.sessions[sid] = session;
      });
  };

  // Restore session from database if available
  //   callback(err, session)
  //
  application.security.restorePersistentSession = function(client, sid, callback) {
    if (application.security.hasDb()) {
      application.databases.security.sessions.findOne({ sid: sid }, function(err, session) {
        if (session) {
          var login = session.login;
          delete session._id;
          session = new application.security.Session(session);
          application.sessions[sid] = session;
          if (login) {
            if (application.users[login]) {
              application.users[login].sessions.push(sid);
              callback(null, session);
            } else {
              application.security.getUser(client, login, function(err, node) {
                if (node) {
                  var user = new application.security.User(node);
                  user.sessions.push(sid);
                  application.users[login] = user;
                } else {
                  delete application.sessions[sid].login;
                  client.sessionModified = true;
                }
                callback(null, session);
              });
            }
          } else callback(null, session);
        } else callback(new Error('Session not found'));
      });
    } else callback(new Error('No database for security subsystem found'));
  };

  

  // Save session to database
  //
  application.security.savePersistentSession = function(client, sid, callback) {
    if (application.security.hasDb() && client.session) {
      client.session.sid = sid;
      if (client.sessionCreated) {
        application.databases.security.sessions.insert(client.session, function(/*err*/) {
          client.sessionCreated = false;
          client.sessionModified = false;
          callback();
        });
      } else if (client.sessionModified) {
        application.databases.security.sessions.update({ sid: sid }, client.session, function(/*err*/) {
          client.sessionCreated = false;
          client.sessionModified = false;
          callback();
        });
      } else callback();
    } else callback();
  };

  // Delete session from database
  //
  application.security.deletePersistentSession = function(client, sid, callback) {
    if (application.security.hasDb()) {
      application.databases.security.sessions.remove({ sid: sid }, true, callback);
    } else callback();
  };

};
