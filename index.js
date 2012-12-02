var http = require('http'),
    connect = require('connect'),
    sio = require('socket.io'),
    RedisStore = require('connect-redis')(connect),
    parseCookie = require('cookie').parse,
    cookieSignature = require('cookie-signature'),
    app = connect(),
    redisOptions = {
      'host': 'localhost',
      'port': '6379',
      'db': 'cloudwizard',
      'pass': ''
    },
    sessionStore = new RedisStore(redisOptions),
    sessionConfig = {
      store: sessionStore,
      secret: 'sp3480oo34t8assti89c',
      key: 'cloudwizard.sid'
    },
    sc_auth_options = {
      host: 'www.soundcloud.com',
      path: '/connection',
      method: 'POST',
      headers: {
        client_id: "2105d18bcf851694947795f67b045675",
        client_secret: "ec9f9415a6203ee7d31f01b09fd94af9",
        redirect_uri: "http://matthewdhowell.com/cloudwizard/receiver/soundcloud"
        // grant_type: "client_credentials",
        // code: "",
        // state: ""
      }
    };

function sessionError(extra) {
  throw Error('Error: Session Unavailable', extra);
}

function socketSessionAuthorization(data, accept) {
  
  // has a cookie header
  if(data.headers.cookie) {
    var cookieDough = parseCookie(data.headers.cookie)[sessionConfig.key].slice(2);
    data.cookie = cookieSignature.unsign(cookieDough, sessionConfig.secret);
    data.sessionID = data.cookie;
    sessionStore.get(data.sessionID, function(err, session) {
      if(err || !session) {
        return accept('Error: Session Unavailable.', false);
      } else {
        session.who = 'cthulu';
        data.session = session;
        return accept(null, true);
      }
    });
  } else {
  
    return accept('Error: Session Unavailable.', false);
  }
}

function getSocketSession(socket) {
  if(!socket || !socket.handshake.session) {
    sessionError();
  }
  return socket.handshake.session;
}

function onSocketConnect(socket) {
  console.log('a socket connected with sid: ' + socket.handshake.sessionID);
  socket.on('get tracks', getTracks);
}

function soundcloudAPIAuth() {
  
}

function getTracks(socket) {
  console.log("get_tracks", arguments);
  var session = getSocketSession(socket);
  var sc_get_tracks_options = {
      token: session['token']
  };
  http.request(sc_get_tracks_options, function(res){
    // this should just be a json passthru
    socket.emit('set_tracks', res.body);
  });
  
}

// Bootstrap-ish stuff happens once Redis is available
function onRedisClientConnect() {
  app.use(connect.static(__dirname + '/public'));
  app.use(connect.cookieParser());
  app.use(connect.session(sessionConfig));
  app.use(function(req, res, err) {
      if(req.method !== 'GET' || req.url.indexOf('/receiver' === -1)){ return next(); }
      var separator = '&',
          parts = decodeURI(req.url).split('?', 1)[0].replace(separator, '').split('/'); 
      console.log(parts);
  });
  var server = http.createServer(app).listen(8080, 'cloudwizard.matthewdhowell.com'),
      io = sio.listen(server);
  io.set('authorization', socketSessionAuthorization);
  io.sockets.on('connection', onSocketConnect);
}


sessionStore.client.on('connect', onRedisClientConnect);
