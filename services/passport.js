const passport = require('passport');
const User = require('../models/user');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');

//create local Strategy
const localOptions = { usernameField: 'email' };

const localLogin = new LocalStrategy(localOptions, function(email, password, done) {
  //verify this username and password, call done with the user if it
  //is the correct email and password
  //otherwise, call done with false

  User.findOne({email: email}, function(err, user) {
    if(err) {return done(err)}
    //if the user does not exist - then return done with the flag false to indicate that
    //authorization failed
    if(!user) { return done(null, false); }

    //compare passwords - is 'password' equal to user.password?
    user.comparePassword(password, function(err, isMatch) {
      if(err) {return done(err) }
      //if wrong password
      if(!isMatch) { return done(null, false) }

      //else we have correct password
      return done(null, user);
    })
  })
});

//setup options for JWT Strategy - this will tell passport where
//to look in the request object to get the token and pull off the payload (id) property
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromHeader('authorization'),
  secretOrKey: config.secret
};

//create JWT Strategy
const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done) {
  //see if the user ID in the payload exists in our database
  //if it does, call 'done' with that user
  //otherwise, call done without a user object
  User.findById(payload.sub, function(err, user) {
    if(err) {return done(err, false); }
    if(user) {
      //user found - return that user
      done(null, user);
    }else {
      //user does not exist
      done(null, false);
    }
  })
})

//tell passport to use this Strategy
passport.use(jwtLogin);
passport.use(localLogin);
