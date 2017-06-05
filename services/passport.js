const passport = require('passport');
const User = require('../models/user');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');

//Create local Strategy
const localOptions = {usernameField: "name"};
const localLogin = new LocalStrategy(localOptions, (name, password, done) => {
  User.findOne({name}, (err, user) => {
    if(err) { return done(err); }
    if(!user) { return done(null, false) };

    user.comparePassword(password, (err, isMatch) => {
      if(err) { return done(err); }
      if(!isMatch) { return done(null, false); }

      return done(null, user);
    });
  })
});

//Setup options for JWT Strategy
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromHeader('authorization'),
  secretOrKey: config.secret
};

//Create jwt Strategy
const jwtLogin = new JwtStrategy(jwtOptions, (payload, done) => {
  User.findById(payload.sub, (err, user) => {
    if(err) {return done(err, false);}

    if(user) {
      done(null, user);
    } else {
      done(null, false);
    }
  });
});

//Use Strategy
passport.use(jwtLogin);
passport.use(localLogin);
