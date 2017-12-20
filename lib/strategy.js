// Load modules.
var OAuth2Strategy = require("passport-oauth2"),
  util = require("util"),
  url = require("url"),
  qs = require("querystring"),
  InternalOAuthError = require("passport-oauth2").InternalOAuthError;

/**
 * `Strategy` constructor.
 *
 * The Yahoo authentication strategy authenticates requests by delegating to
 * Yahoo using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `cb`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your Yahoo application's client id
 *   - `clientSecret`  your Yahoo application's client secret
 *   - `callbackURL`   URL to which Yahoo will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new YahooStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/Yahoo/callback',
 *         redirectParams: {
 *           custom_token: 'perhapsyouruserId'
 *         }
 *       },
 *       function(accessToken, refreshToken, params, profile, cb) {
 *         User.findOrCreate(..., function (err, user) {
 *           cb(err, user);
 *         });
 *       }
 *     ));
 *
 * @constructor
 * @param {object} options
 * @param {function} verify
 * @access public
 */
function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL =
    options.authorizationURL ||
    "https://api.login.yahoo.com/oauth2/request_auth";
  options.tokenURL =
    options.tokenURL || "https://api.login.yahoo.com/oauth2/get_token";
  options.callbackURL = options.redirectParams
    ? `${options.callbackURL}?${qs.stringify(options.redirectParams)}`
    : options.callbackURL;

  OAuth2Strategy.call(this, options, verify);
  this.name = "yahoo-oauth2";
}

// Inherit from `OAuth2Strategy`.
util.inherits(Strategy, OAuth2Strategy);
/**
 * Pretty much the same as parent function but allowing params object to get passed
 *
 * @param {any} req
 * @param {any} options
 * @returns
 */
Strategy.prototype.authenticate = function(req, options) {
  options = options || {};
  var self = this;

  if (req.query && req.query.error) {
    if (req.query.error == "access_denied") {
      return this.fail({ message: req.query.error_description });
    } else {
      return this.error(
        new AuthorizationError(
          req.query.error_description,
          req.query.error,
          req.query.error_uri
        )
      );
    }
  }

  var callbackURL = options.callbackURL || this._callbackURL;
  if (callbackURL) {
    var parsed = url.parse(callbackURL);
    if (!parsed.protocol) {
      // The callback URL is relative, resolve a fully qualified URL from the
      // URL of the originating request.
      callbackURL = url.resolve(
        util.originalURL(req, { proxy: this._trustProxy }),
        callbackURL
      );
    }
  }

  var meta = {
    authorizationURL: this._oauth2._authorizeUrl,
    tokenURL: this._oauth2._accessTokenUrl,
    clientID: this._oauth2._clientId
  };

  if (req.query && req.query.code) {
    function loaded(err, ok, state) {
      if (err) {
        return self.error(err);
      }
      if (!ok) {
        return self.fail(state, 403);
      }

      var code = req.query.code;

      var paramsOuter = self.tokenParams(options);
      paramsOuter.grant_type = "authorization_code";
      if (callbackURL) {
        paramsOuter.redirect_uri = callbackURL;
      }

      self._oauth2.getOAuthAccessToken(code, paramsOuter, function(
        err,
        accessToken,
        refreshToken,
        params
      ) {
        if (err) {
          return self.error(
            self._createOAuthError("Failed to obtain access token", err)
          );
        }

        self._loadUserProfile(accessToken, params, function(err, profile) {
          if (err) {
            return self.error(err);
          }

          function verified(err, user, info) {
            if (err) {
              return self.error(err);
            }
            if (!user) {
              return self.fail(info);
            }

            info = info || {};
            if (state) {
              info.state = state;
            }
            self.success(user, info);
          }

          try {
            if (self._passReqToCallback) {
              var arity = self._verify.length;
              if (arity == 6) {
                self._verify(
                  req,
                  accessToken,
                  refreshToken,
                  params,
                  profile,
                  verified
                );
              } else {
                // arity == 5
                self._verify(req, accessToken, refreshToken, profile, verified);
              }
            } else {
              var arity = self._verify.length;
              if (arity == 5) {
                self._verify(
                  accessToken,
                  refreshToken,
                  params,
                  profile,
                  verified
                );
              } else {
                // arity == 4
                self._verify(accessToken, refreshToken, profile, verified);
              }
            }
          } catch (ex) {
            return self.error(ex);
          }
        });
      });
    }

    var state = req.query.state;
    try {
      var arity = this._stateStore.verify.length;
      if (arity == 4) {
        this._stateStore.verify(req, state, meta, loaded);
      } else {
        // arity == 3
        this._stateStore.verify(req, state, loaded);
      }
    } catch (ex) {
      return this.error(ex);
    }
  } else {
    var params = this.authorizationParams(options);
    params.response_type = "code";
    if (callbackURL) {
      params.redirect_uri = callbackURL;
    }
    var scope = options.scope || this._scope;
    if (scope) {
      if (Array.isArray(scope)) {
        scope = scope.join(this._scopeSeparator);
      }
      params.scope = scope;
    }

    var state = options.state;
    if (state) {
      params.state = state;

      var parsed = url.parse(this._oauth2._authorizeUrl, true);
      util.merge(parsed.query, params);
      parsed.query["client_id"] = this._oauth2._clientId;
      delete parsed.search;
      var location = url.format(parsed);
      this.redirect(location);
    } else {
      function stored(err, state) {
        if (err) {
          return self.error(err);
        }

        if (state) {
          params.state = state;
        }
        var parsed = url.parse(self._oauth2._authorizeUrl, true);
        util.merge(parsed.query, params);
        parsed.query["client_id"] = self._oauth2._clientId;
        delete parsed.search;
        var location = url.format(parsed);
        self.redirect(location);
      }

      try {
        var arity = this._stateStore.store.length;
        if (arity == 3) {
          this._stateStore.store(req, meta, stored);
        } else {
          // arity == 2
          this._stateStore.store(req, stored);
        }
      } catch (ex) {
        return this.error(ex);
      }
    }
  }
};
/**
 * Use a different meothod of the OAuth2Strategy to allow for necessary params object
 * Otherwise the profile gathering would occur in the verify callback
 *
 * @param {string} accessToken
 * @param {object} params
 * @param {function} done
 * @access private
 */
Strategy.prototype._loadUserProfile = function(accessToken, params, done) {
  var self = this;

  function loadIt() {
    return self.userProfile(accessToken, params, done);
  }
  function skipIt() {
    return done(null);
  }

  if (
    typeof this._skipUserProfile == "function" &&
    this._skipUserProfile.length > 1
  ) {
    // async
    this._skipUserProfile(accessToken, function(err, skip) {
      if (err) {
        return done(err);
      }
      if (!skip) {
        return loadIt();
      }
      return skipIt();
    });
  } else {
    var skip =
      typeof this._skipUserProfile == "function"
        ? this._skipUserProfile()
        : this._skipUserProfile;
    if (!skip) {
      return loadIt();
    }
    return skipIt();
  }
};
/**
 * Retrieve user profile from Yahoo.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `yahoo`
 *   - `id`
 *   - `username`
 *   - `displayName`
 *
 * @param {string} accessToken
 * @param {object} params
 * @param {function} done
 * @access protected
 */
Strategy.prototype.userProfile = function(accessToken, params, done) {
  var self = this;
  const profileUrl =
    "https://social.yahooapis.com/v1/user/" +
    params.xoauth_yahoo_guid +
    "/profile?format=json";
  this._oauth2.get(profileUrl, accessToken, function(err, body, res) {
    if (err) {
      return done(new InternalOAuthError("failed to fetch user profile", err));
    }
    if (body.error) {
      let message;
      try {
        message = body.error.detail.content[0];
      } catch (e) {
        console.log(e);
        message = JSON.stringify(body.error, null, 4);
      }
      return done(new InternalOAuthError(message, new Error()));
    }
    try {
      var json = JSON.parse(body);

      var profile = { provider: "yahoo" };

      profile.id = json.guiid;
      profile.displayName = json.name.nickname;
      profile.avatar = json.profile.image.imageUrl;
      //   profile.name = {
      //     familyName: json.name.surname,
      //     givenName: json.name.given_name,
      //     middleName: ''
      //   };
      //   profile.emails = [{ value: json.email }];

      profile._raw = body;
      profile._json = json;

      done(null, profile);
    } catch (e) {
      done(e);
    }
  });
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
