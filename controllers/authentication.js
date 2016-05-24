const User = require('../models/user');
const jwt = require('jwt-simple');
const config = require('../config');

function tokenForUser(user) {
  const timestamp = new Date().getTime();
  return jwt.encode({sub: user.id, iat: timestamp }, config.secret)
}

exports.signin = function(req, res, next) {
  //user has already had their email and password auth'd
  //we just need to give them a token
  //passport attaches the user object to req.body after authorization
  res.send({ token: tokenForUser(req.user) });
}

exports.signup = function(req, res, next) {
  const email = req.body.email;
  const password = req.body.password;

  //check to see all information is provided
  if(!email || !password) {
    return res.status(422).send({error: 'You must provide email and password'})
  }

  //see if a user with the given email exists
  User.findOne({email: email}, function(err, existingUser) {
    if(err) {return next(err)}

    //if user with email does exist, return an Error
    if(existingUser) {
      return res.status(422).send({error: 'email is in use'});
    }

    //if a user with email does NOT exist, create and save user record
    const user = new User({
      email: email,
      password: password
    });

    //saves the record to the db
    user.save(function(err, user){
      if(err) { return next(err); }

      // respond to request indicating the user was created and issue jwt
      res.json({token: tokenForUser(user)});
    });
  });
}
