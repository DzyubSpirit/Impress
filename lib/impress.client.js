'use strict';

// HTTP Client interface for Impress Application Server
//

// Client class
//   application - instance of application
//   req - request is an instance of http.IncomingMessage
//   res - rsponse is an instance of http.ServerResponse
//
var Client = function(application, req, res) {
  var client = this,
      socket = req.socket || req.connection.socket,
      server = impress.config.servers[socket.server.serverName],
      url = api.url.parse(req.url);

  client.startTime = Date.now();
  client.prevTime = client.startTime;

  Client.counter++;
  client.isTimerActive = false;
  if (Client.counter === 50000) {
    Client.counter = 0;
    client.isTimerActive = true;
  }

  req.connection.client = client;
  client.req = req;
  client.res = res;
  client.socket = socket;
  client.server = server;
  client.dynamicHandler = false;
  client.application = application;
  client.query = api.querystring.parse(url.query);
  client.schema = server.protocol;
  client.method = req.method.toLowerCase();
  client.access = api.impress.clone(impress.DEFAULT_ACCESS);
  client.calculateAccess();
  client.parameters = {};
  api.impress.extend(client.parameters, client.query);
  client.slowTime = server.slowTime;
  client.timedOut = false;
  client.finished = false;
  client.url = url.pathname;
  client.host = api.impress.parseHost(req.headers.host);
  client.path = api.impress.addTrailingSlash(client.url);
  client.pathDir = application.dir + '/server' + client.path;
  client.realPath = client.path;
  client.realPathDir = client.pathDir;
  client.execPath = client.path;
  client.execPathDir = client.pathDir;
  client.ext = api.impress.fileExt(client.path);
  client.typeExt = client.ext || 'html';
  client.data = ''; // data received from client
  client.chunks = []; // for large requests receiving in chunks
  client.ip = (
    req.headers['x-forwarded-for'] ||
    req.connection.remoteAddress ||
    socket.remoteAddress
  );
  if (client.ip) {
    client.ip = client.ip.replace(impress.REGEXP_IPV4_TO_IPV6, '');
    client.ipInt = api.impress.ip2int(client.ip);
    impress.waf.ip.inc(client.ipInt);
    client.local = api.impress.inArray(api.impress.localIPs, client.ip);
  }

  client.cookies = {}; // received cookies
  client.preparedCookies = []; // cookies to send

  if (res.setHeader) {
    var contentType = impress.MIME_TYPES[client.typeExt];
    if (contentType) res.setHeader('Content-Type', contentType);
    res.setHeader('Cache-Control', 'public');
    res.setHeader('Keep-Alive', 'timeout=' + ~~(server.keepAliveTimeout / 1000));
  }

  // Socket leak workaround
  res.on('finish', function() {
    socket.removeAllListeners('timeout');
    socket.setTimeout(server.keepAliveTimeout || impress.DEFAULT_KEEP_ALIVE_INTERVAL, function() {
      socket.destroy();
    });
  });

  res.on('close', function() {
    impress.waf.ip.dec(client.ipInt);
    impress.waf.sid.dec(client.ipInt);
  });
};

impress.Client = Client;
impress.Client.prototype.application = impress;

// Access log client request
//
Client.prototype.accessLog = function() {
  var client = this,
      application = client.application;

  if (application) {
    client.endTime = Date.now();
    var location = '-';
    if (api.geoip) {
      var geo = api.geoip.lookup(client.ip);
      if (geo) location = geo.country + '/' + geo.region + '/' + geo.city;
    }
    var msg = (
      client.endTime - client.startTime + 'ms\t' +
      client.ip + '\t' +
      location + '\t' +
      ((client.user ? client.user.login : '-') || '-') + '\t' +
      (client.sid || '-') + '\t' +
      client.socket.bytesRead + '\t' +
      client.socket.bytesWritten + '\t' +
      client.req.method + '\t' +
      client.res.statusCode + '\t' +
      client.schema + '://' + client.req.headers.host + client.url + '\t' +
      client.req.headers['user-agent'] + '\t' +
      client.req.headers['referer']
    );
    application.log.access(msg);
    if (client.endTime - client.startTime >= client.slowTime) application.log.slow(msg);
  }
};

// Fork long worker
//   workerFile - handler to be executed in forked process
//
Client.prototype.fork = function(workerFile) {
  var client = this,
      application = client.application,
      user = client.user;

  if (client.application) {
    var clientData = {
      url: client.url,
      query: client.query,
      sid: client.sid,
      session: client.session,
      context: client.context,
      fields: client.fields,
      parameters: client.parameters,
      user: null
    };
    if (user) clientData.user = {
      login: user.login,
      access: user.access,
      data: user.data
    };
    var fileName = client.pathDir + workerFile + '.js';
    impress.forkLongWorker(application.name, fileName, JSON.stringify(clientData));
  }
};

// Kill long worker
//   workerFile - name of handler file to identify process
//
Client.prototype.killLongWorker = function(workerFile) {
  var fileName = this.pathDir + workerFile + '.js';
  if (this.application) impress.killLongWorker(this.application.name, fileName);
};

// Start session
//
Client.prototype.startSession = function() {
  var client = this,
      application = client.application;

  if (application && !client.session) {
    client.sid = api.impress.generateSID(application.config);
    client.user = new application.User();
    client.session = new application.Session({ sid: client.sid });
    client.sessionModified = true;
    client.sessionCreated = true;
    client.setCookie(application.config.sessions.cookie, client.sid, application.config.sessions.domain);
    if (impress.config.scale.cookie) client.setCookie(impress.config.scale.cookie, impress.nodeId);
    application.sessions[client.sid] = client.session;
  }
};

// Destroy session
//
Client.prototype.destroySession = function() {
  var client = this,
      application = client.application;

  if (application && client.session) {
    client.deleteCookie(application.config.sessions.cookie, application.config.sessions.domain);
    client.deleteCookie(impress.config.scale.cookie, application.config.sessions.domain);
    // clear other structures
    var login = client.session.login;
    if (login && application.users[login]) delete application.users[login].sessions[client.sid];
    delete application.sessions[client.sid];
    // TODO: delete session from DB persistent session storage
    application.security.deletePersistentSession(client.sid, api.impress.emptyness);
    client.sid = null;
    client.user = null;
    client.session = null;
  }
};

// Parse cookies
//
Client.prototype.parseCookies = function() {
  var client = this;

  var cookies = client.req.headers.cookie;
  if (cookies) cookies.split(';').forEach(function(cookie) {
    var parts = cookie.split('=');
    client.cookies[api.impress.trim(parts[0])] = api.impress.trim(parts[1] || '');
  });
};

// Set cookie
//   name - cookie name
//   value - cookie value
//   host - host name (optional)
//   httpOnly - boolean HttpOnly cookie modifier (optional)
//
Client.prototype.setCookie = function(name, value, host, httpOnly) {
  var expires = new Date(2100, 1, 1).toUTCString();
  host = host || this.req.headers.host;
  var pos = host.indexOf(':');
  if (pos > -1) host = host.substring(0, pos);
  if (httpOnly === undefined) httpOnly = true;
  this.preparedCookies.push(
    name + '=' + value + '; expires=' + expires + '; Path=/; Domain=' + host + (httpOnly ? '; HttpOnly' : '')
  );
};

// Delete cookie by name
//   name - cookie name
//   host - host name
//
Client.prototype.deleteCookie = function(name, host) {
  var aHost = host || this.req.headers.host;
  if (api.net.isIP(aHost) === 0) aHost = '.' + aHost;
  this.preparedCookies.push(name + '=deleted; Expires=Thu, 01 Jan 1970 00:00:01 GMT; Path=/; Domain=' + aHost);
};

// Send cookies prepared in client.cookies
//
Client.prototype.sendCookie = function() {
  if (this.preparedCookies && this.preparedCookies.length && !this.res.headersSent) {
    this.res.setHeader('Set-Cookie', this.preparedCookies);
  }
};

// Route request to external HTTP server
//   host - forward request to nost name or IP address
//   port - request port number (number)
//   url - request URL string
//
Client.prototype.proxy = function(host, port, url) {
  var client = this,
      application = client.application;

  var req = api.http.request({
    hostname: host,
    port: port,
    path: url,
    method: client.req.method
  }, function(response) {
    client.res.writeHead(response.statusCode, response.headers);
    response.on('data', function(chunk) {
      client.res.write(chunk);
    });
    response.on('end', function() {
      client.end();
    });
  });
  req.on('error', function(err) {
    if (application) application.log.error('Error proxying request: ' + err.message);
  });
  req.end();
  impress.stat.responseCount++;
};

// Dispatch dynamic request
//
Client.prototype.dispatch = function() {
  var client = this;
  
  client.timer('dispatch');

  client.dynamicHandler = true;
  client.parseCookies();

  client.timer('parseCookies');

  var code = impress.waf.check(client);
  
  client.timer('waf');

  if (code === impress.waf.ACCESS_ALLOWED) {
    client.restoreSession(function() {
      client.detectRealPath(function() {
        client.processing();
      });
    });
  } else if (code === impress.waf.ACCESS_DENIED) client.error(403);
  else if (code === impress.waf.ACCESS_LIMITED) client.error(429);
  else client.error(400);
};

// Add current client to deny list by IP and SID (if session exists)
//
Client.prototype.block = function(msec) {
  var client = this;

  client.error(403);
  msec = api.impress.duration(msec) || 0;
  impress.waf.ip.deny(client.ipInt);
  if (client.sid) impress.waf.sid.deny(client.sid);
};

// Restore session if available
//   callback - call when session is restored
//
Client.prototype.restoreSession = function(callback) {
  var client = this,
      application = client.application;

  client.timer('restoreSession');

  if (application) {
    client.parseCookies();
    var sid = client.cookies[application.config.sessions.cookie];
    if (sid) {
      var session = application.sessions[sid];
      if (session) client.setSession(sid, session);
      else {
        if (api.impress.validateSID(application.config, sid) && application.config.sessions.persist) {
          var cb = callback;
          callback = null;
          application.security.restorePersistentSession(client, sid, function(err, session) {
            if (session) client.setSession(sid, session);
            else client.deleteCookie(application.config.sessions.cookie);
            cb();
          });
        } client.deleteCookie(application.config.sessions.cookie);
      }
    }
  }
  if (callback) callback();
};

// Set session for client instance
//   sid - session identifier
//   session - object/hash with session fields
//
Client.prototype.setSession = function(sid, session) {
  var client = this,
      application = client.application;

  client.sid = sid;
  client.session = session;
  client.logged = !!client.session.login;
  client.user = application.security.getSessionUser(sid);
};

// Save session
//
Client.prototype.saveSession = function(callback) {
  var client = this,
      application = client.application;

  if (application && application.config.sessions && application.config.sessions.persist &&
    client.session && (client.sessionCreated || client.sessionModified)
  ) application.security.savePersistentSession(client, client.sid, callback);
  else callback();
};

// Process request
//
Client.prototype.processing = function() {
  var client = this,
      application = client.application;

  client.timer('processing');

  var cache = application.cache.pages[client.realPath];
  if (cache && (client.startTime < cache.expireTime)) client.sendCache(cache);
  else {
    client.ext = api.impress.fileExt(client.realPath);
    client.typeExt = client.ext || 'html';

    var handlers = ['access', 'request', client.method, 'end', 'lazy'];
    client.context = {};

    // Set Content-Type if detected and not SSE
    if (client.typeExt === 'sse') client.eventChannel = null;
    else if (client.typeExt !== 'ws' && !client.res.headersSent) client.defaultContentType();

    // Initialize long connections: SSE, WebSocket, Impress RPC
    if (client.ext === 'ws' && application.websocket) application.websocket.initialize(client);
    if (client.ext === 'rpc' && application.rpc) application.rpc.initialize(client);

    // Execute handlers
    api.async.eachSeries(handlers, function(handler, cb) {

      client.timer('handler ' + handler);

      if (handler === 'access' || client.access.virtual || client.path === client.realPath ) {
        client.execPath = client.realPath;
        client.execPathDir = client.realPathDir;
        client.fileHandler(handler, false, cb);
      } else {
        client.error(404);
        cb(new Error(404));
      }
    }, function(err) {
      if (!err && !client.res.headersSent) {
        if (client.access.allowed) {
          if (client.access.auth && !client.local) return client.basicAuth();
          if (client.ext === '' && client.access.intro) client.introspect();
          else {
            var extCase = client.extCases[client.typeExt] || client.extCases['html'];
            if (extCase) extCase(client, application); else client.error(404);
          }
        } else client.error(403);
      }
    });
  }
};

// Extension finalization cases
//
Client.prototype.extCases = {};

// HTML finalization
//
Client.prototype.extCases['html'] = function(client, application) {
  if (typeof(client.context.data) === 'string') client.end(client.context.data);
  else client.processingPage();
};

// SSE finalization
//
Client.prototype.extCases['sse'] = function(client, application) {
  if (application.sse) client.sseConnect();
  else client.error(510);
};

// WS finalization
//
Client.prototype.extCases['ws'] = function(client, application) {
  if (application.websocket) application.websocket.finalize(client);
  else client.error(510);
};

// RPC finalization
//
Client.prototype.extCases['rpc'] = function(client, application) {
  if (application.rpc) application.rpc.finalize(client);
  else {
    if (application.websocket) {
      application.websocket.initialize(client);
      application.websocket.finalize(client);
    } else client.error(510);
  }
};

// JSON finalization
//
Client.prototype.extCases['json'] = function(client, application) {
  if (client.context.data) client.end(JSON.stringify(client.context.data));
  else client.error(400);
};

// JSONP finalization
//
Client.prototype.extCases['jsonp'] = function(client /*application*/) {
  if (client.context.data) {
    var jsonpCallbackName =  client.query['callback'] || client.query['jsonp'] || 'callback';
    client.end(jsonpCallbackName + '(' + JSON.stringify(client.context.data) + ');');
  } else client.error(400);
};

// CSV finalization
//
Client.prototype.extCases['csv'] = function(client /*application*/) {
  if (client.context.data) {
    api.csv.stringify(client.context.data, function(err, data) {
      client.end(data);
    });
  } else client.error(400);
};

// Start basic HTTP auth
//
Client.prototype.basicAuth = function() {
  var client = this;

  var authBase64 = client.req.headers['authorization'],
      authAllowed = false;
  if (authBase64) {
    authBase64 = authBase64.substring(6);
    var auth = new Buffer(authBase64, 'base64');
    authAllowed = client.access.auth === auth.toString();
  }
  if (!authAllowed) {
    var realm = client.access.realm || 'Restricted';
    client.res.setHeader('WWW-Authenticate', 'Basic realm="' + realm + '"');
    client.error(401);
  }
};

// Detect and send Content-Type
//
Client.prototype.defaultContentType = function() {
  var client = this,
      application = client.application;

  var contentType = impress.MIME_TYPES[client.typeExt];
  if (contentType) client.res.setHeader('Content-Type', contentType);
  var allowOrigin = api.impress.getByPath(application.config, 'application.allowOrigin');
  if (allowOrigin) {
    client.res.setHeader('Access-Control-Allow-Origin', allowOrigin);
    client.res.setHeader('Access-Control-Allow-Headers', 'origin, content-type, accept');
  }
};

// Process dynamic and static pages, cms pages
//
Client.prototype.processingPage = function() {
  var client = this;

  var data = client.context.data || {};
  client.execPath = client.realPath;
  client.execPathDir = client.realPathDir;
  client.template(data, 'html', '', function(tpl) {
    client.end(tpl);
  });
};

// Cache URL response
//   timeout - in number of milliseconds or string in duration format, e.g. '10h 30m' or '30s'
//
Client.prototype.cache = function(timeout) {
  this.context.cache = api.impress.duration(timeout);
};

// End request
//   output - reply (string)
//
Client.prototype.end = function(output) {
  var client = this;

  var isBuffer = output instanceof Buffer,
      length = output ? output.length : 0;
  client.finished = true;
  if (client.ipInt) impress.waf.ip.dec(client.ipInt);
  client.saveSession(function() {
    client.sendCookie();
    if (!client.res.headersSent) {
      if (client.stats) {
        client.res.setHeader('Content-Length', client.stats.size);
        client.res.setHeader('Last-Modified', client.stats.mtime.toGMTString());
      }
      if (client.compressed) client.res.setHeader('Content-Encoding', 'gzip');
    }
    if (!isBuffer && length > impress.COMPRESS_ABOVE) {
      api.zlib.gzip(output, function(err, data) {
        if (err) client.error(500, err);
        else {
          if (!client.res.headersSent && client.res.setHeader) {
            client.res.setHeader('Content-Encoding', 'gzip');
            client.res.setHeader('Content-Length', data.length);
            client.res.end(data);
            if (client.context && client.context.cache) client.saveCache(data);
          } else client.res.end();
        }
      });
    } else {
      client.res.end(output);
      if (client.context && client.context.cache) client.saveCache(output);
    }
    client.accessLog();
    impress.stat.responseCount++;
  });
};

// Save cache
//   output - reply (string)
//
Client.prototype.saveCache = function(output) {
  var client = this,
      application = client.application,
      now = new Date();

  application.cache.pages[client.realPath] = {
    expireTime: client.startTime + client.context.cache,
    statusCode: client.res.statusCode,
    contentType: client.res.getHeader('content-type'),
    contentEncoding: client.res.getHeader('content-encoding'),
    stats: { size: output.length, mtime: now.getTime(), time: now.toGMTString() },
    data: output
  };
};

// Send cache to client side
//   cache - structure { stats, data }
//
Client.prototype.sendCache = function(cache) {
  var client = this;

  client.res.statusCode = cache.statusCode;
  if (cache.contentType) client.res.setHeader('Content-Type', cache.contentType);
  if (cache.contentEncoding) client.res.setHeader('Content-Encoding', cache.contentEncoding);
  if (cache.stats) {
    client.res.setHeader('Content-Length', cache.stats.size);
    client.res.setHeader('Last-Modified', cache.stats.time);
  }
  client.end(cache.data);
};

// End request with HTTP error code
//   code - HTTP status code
//   err - instance of Error class (optional)
//
Client.prototype.error = function(code, err) {
  var client = this,
      application = client.application;

  if (err) client.err = err;
  client.res.statusCode = code;
  client.fileHandler('error', false, function() {
    if (code === 304) client.end(); else {
      if (client.typeExt === 'json') client.end('{"statusCode":' + code + '}');
      else {
        if (client.res.headersSent === false) client.res.setHeader('Content-Type', impress.MIME_TYPES['html']);
        var message = impress.STATUS_CODES[code] || 'Unknown error';
        client.include(
          { title: 'Error ' + code, message: message },
          application.systemTemplates['error'] || '', '',
          function(tpl) {
            client.end(tpl);
          }
        );
        application.log.error('HTTP ' + code + '\t' + message + '\t' + client.url);
      }
    }
  });
};

// Redirect to specified location
//   location - URL
//
Client.prototype.redirect = function(location) {
  if (!this.res.headersSent) {
    this.res.setHeader('Location', location);
    this.res.statusCode = 302;
  }
};

// Inherit behavior from parent folder
//   callback - call after inherited handler executed
//
Client.prototype.inherited = function(callback) {
  var client = this,
      application = client.application;

  if (client.execPath !== '/' && client.currentHandler !== 'meta') {
    client.execPath = api.impress.dirname(client.execPath) + '/';
    client.execPathDir = application.dir + '/server' + client.execPath;
    client.fileHandler(client.currentHandler, true, callback);
  }
};

// Find existent file to execute
//   handler - handler file name: 'access', 'request', 'end', 'lazy', 'error' and HTTP methods: 'get', 'post', 'put', 'delete', 'patch', 'head', 'options'
//   inheritance - boolean flag, true if called from Client.prototype.inherited
//   callback - call after fileHandler executed
//
Client.prototype.fileHandler = function(handler, inheritance, callback) {
  var client = this,
      application = client.application;

  var fileName = handler + '.js',
      filePath = client.execPathDir + fileName,
      relPath = application.relative(filePath),
      fileCache = application.cache.files[relPath];

  if (!inheritance) client.currentHandler = handler;
  if (fileCache) {
    if (fileCache === impress.FILE_EXISTS) client.runScript(handler, filePath, callback);
    else callback();
  } else api.fs.exists(filePath, function(exists) {
    if (exists) {
      client.runScript(handler, filePath, callback);
      if (!inheritance) application.cache.files[relPath] = impress.FILE_EXISTS;
      application.watchCache(api.path.dirname(relPath));
    } else {
      // Try to process request on parent directory
      if (client.execPath !== '/' && handler !== 'meta') {
        client.execPath = api.impress.dirname(client.execPath);
        client.execPathDir = application.dir + '/server' + client.execPath;
        client.fileHandler(handler, inheritance, callback);
        application.watchCache('/server' + client.execPath);
      } else {
        // Lose hope to execute request and drop connection
        if (!inheritance) application.cache.files[relPath] = impress.FILE_NOT_FOUND;
        application.watchCache(api.path.dirname(relPath));
        callback();
      }
    }
  });
};

// Find nearest existent folder
//   callback - call after path detected
//
Client.prototype.detectRealPath = function(callback) {
  var client = this,
      application = client.application;

  client.timer('detectRealPath');

  var relPath = application.relative(client.realPathDir),
      folderCache = application.cache.folders[relPath];
  if ((folderCache && folderCache !== impress.DIR_NOT_EXISTS) || client.realPath === '/') callback();
  else api.fs.exists(client.realPathDir, function(exists) {
    if (exists) {
      application.cache.folders[relPath] = impress.DIR_EXISTS;
      callback();
    } else {
      application.cache.folders[relPath] = impress.DIR_NOT_EXISTS;
      client.realPath = api.impress.dirname(client.realPath);
      client.realPathDir = application.dir + '/server' + client.realPath;
      relPath = application.relative(client.realPathDir);
      client.detectRealPath(callback);
    }
    application.watchCache(api.impress.stripTrailingSlash(relPath));
  });
};

// Calculate access
//
Client.prototype.calculateAccess = function() {
  this.access.allowed = (
    (
      (!this.logged && this.access.guests) ||
      (!!this.logged && this.access.logged)
    ) && (
      (this.schema === 'http' && this.access.http) ||
      (this.schema === 'https' && this.access.https)
    )
  );
  if (this.logged) this.access.allowed = this.access.allowed && (
    (!this.access.groups) ||
    (this.access.groups &&
      (
        this.access.groups.length === 0 ||
        api.impress.inArray(this.access.groups, this.user.group) ||
        api.impress.inArray(this.access.groups, 'local') && this.local
      )
    )
  );
};

// Run script in client context
//   handler - handler name
//   fileName - file name
//   callback - call after handler executed
//
Client.prototype.runScript = function(handler, fileName, callback) {
  var client = this,
      application = client.application;

  application.createScript(fileName, function(err, fn) {
    if (err) {
      client.err = err;
      callback();
    } else if (handler === 'access') {
      client.access = api.impress.extend(client.access, fn);
      client.calculateAccess();
      callback();
    } else if (client.access.allowed && client.application) {
      var fnWrapper = function() {
        if (fn && fn.meta) {
          var vd = api.definition.validate(client.parameters, fn.meta, 'parameters', true);
          if (!vd.valid) {
            client.context.data = fn.meta;
            client.res.statusCode = 400;
            fn = null;
          }
        }
        if (typeof(fn) === 'function') {
          var callbackCalled = false;
          try {
            if (fn.length === 2) {
              // Execute Impress handlers
              fn(client, function(result, errorCode, headers) {
                if (result !== undefined) client.context.data = result;
                if (errorCode) client.res.statusCode = errorCode;
                if (headers && !client.res.headersSent) {
                  if (typeof(headers) === 'string') client.res.setHeader('Content-Type', headers);
                  else for (var headerName in headers) client.res.setHeader(headerName, headers[headerName]);
                }
                callback();
                callbackCalled = true;
              });
            } else if (fn.length === 3) {
              // Execute middleware handlers
              fn(client.req, client.res, function() {
                callback();
                callbackCalled = true;
              });
            } else {
              callback();
              callbackCalled = true;
            }
          } catch(err) {
            client.err = err;
            application.catchException(err);
            if (!callbackCalled) callback();
          }
        } else callback();
      };
      // Refactor: remove .client link from domain because multiple clients within domain may overlap
      application.domain.client = client;
      if (handler === 'lazy') {
        var cb = callback;
        callback = api.impress.emptyness;
        setImmediate(function() {
          application.domain.run(fnWrapper);
        });
        cb();
      } else application.domain.run(fnWrapper);
    } else callback();
  });
};

// Send static file and drop connection
//   callback - if not static
//
Client.prototype.static = function(callback) {
  var client = this,
      application = client.application;

  var filePath = api.impress.stripTrailingSlash(application.dir + '/static' + client.path),
      relPath = application.relative(filePath),
      buffer = application.cache.static[application.relative(filePath)];
  if (buffer) {
    if (typeof(buffer) !== 'number') {
      var sinceTime = client.req.headers['if-modified-since'];
      if (sinceTime && api.impress.isTimeEqual(sinceTime, buffer.stats.mtime)) client.error(304);
      else {
        client.stats = buffer.stats;
        client.compressed = buffer.compressed;
        client.end(buffer.data);
      }
    } else callback();
  } else api.fs.stat(filePath, function(err, stats) {
    if (err) {
      application.cache.static[relPath] = impress.FILE_NOT_FOUND;
      application.watchCache(api.path.dirname(relPath));
      callback();
    } else {
      var sinceTime = client.req.headers['if-modified-since'];
      if (sinceTime && api.impress.isTimeEqual(sinceTime, stats.mtime)) client.error(304);
      else if (stats.isDirectory()) {
        var fileIndex = filePath + '/index.html',
            relIndex = application.relative(fileIndex);
        api.fs.stat(fileIndex, function(err, stats) {
          if (err) {
            application.cache.static[relIndex] = impress.FILE_NOT_FOUND;
            application.watchCache(api.path.dirname(relIndex));
            if (client.path === '/') callback();
            else client.index(filePath);
          } else {
            if (sinceTime && api.impress.isTimeEqual(sinceTime, stats.mtime)) client.error(304);
            else client.compress(fileIndex, stats);
          }
        });
      } else if (stats.size < application.config.files.cacheMaxFileSize) client.compress(filePath, stats);
      else client.stream(filePath, stats);
    }
  });
};

// Refresh static in memory cache with compression and minification
//   filePath - path to handler (from application base directory)
//   stats - instance of fs.Stats
//
Client.prototype.compress = function(filePath, stats) {
  var client = this,
      application = client.application;

  application.compress(filePath, stats, function(err, data, compressed) {
    if (err) client.error(404);
    else {
      client.stats = stats;
      client.compressed = compressed;
      client.end(data);
    }
  });
};

// Global class counter
//
Client.counter = 0;

// Log time measurement from client instance creation
//
Client.prototype.timer = function(msg) {
  var client = this;
  if (client.isTimerActive) {
    var now = Date.now();
    console.log(msg + ':  ' + (now - client.startTime) + ' / ' + (now - client.prevTime));
    client.prevTime = now;
  }
};
