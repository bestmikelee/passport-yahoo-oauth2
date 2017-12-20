# Passport-Yahoo-OAuth2

[Passport](http://passportjs.org/) strategy for authenticating with [Yahoo](https://Yahoo.com/)
using the OAuth 2.0 API.

This module lets you authenticate using Yahoo in your Node.js applications.
By plugging into Passport, Yahoo authentication can be easily and
unobtrusively integrated into any application or framework that supports
[Connect](http://www.senchalabs.org/connect/)-style middleware, including
[Express](http://expressjs.com/).

## Usage

### Configure Strategy

The Yahoo authentication strategy authenticates users using a Yahoo account
and OAuth 2.0 tokens. The strategy requires a `verify` callback, which accepts
these credentials and calls `done` providing a user, as well as `options`
specifying a API version, client ID, client secret, and callback URL.

    passport.use(new YahooOAuth2Strategy({
        clientID: YAHOO_CLIENT_ID,
        clientSecret: YAHOO_CLIENT_SECRET,
        callbackURL: "https://www.example.net/auth/Yahoo-oauth2/callback",
        redirectParams: {
            existingUserId: '12345',
            otherToken: OTHER_TOKEN
        }
      },
      function(accessToken, refreshToken, params, profile, done) {
        User.findOrCreate({ providerId: profile.id }, function (err, user) {
          return done(err, user);
        });
      }
    ));

### Authenticate Requests

Use `passport.authenticate()`, specifying the `'yahoo-oauth2'` strategy, to
authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

    app.get('/auth/yahoo',
      passport.authenticate('yahoo-oauth2'));

    app.get('/auth/yahoo/callback',
      passport.authenticate('yahoo-oauth2', { failureRedirect: '/login' }),
      function(req, res) {
        // Successful authentication, redirect home.
        res.redirect('/');
      });

## Examples

Examples not yet provided

## Tests

Tests not yet provided

## Prior work

This strategy is based on Jared Hanson's GitHub strategy for passport: [Jared Hanson](http://github.com/jaredhanson)

Copyright (c) 2017 Mike Lee
