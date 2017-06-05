const jwt = require('jwt-simple');
const User = require('../models/user');
const config = require('../config');

function tokenForUser(user) {
  const timestamp = new Date().getTime();
  return jwt.encode({sub: user.id, iat: timestamp}, config.secret);
}

exports.signin = function(req, res, next) {
  //Get user token
  res.send({token: tokenForUser(req.user)});
}

exports.signup = function(req, res, next) {
  const name = req.body.name;
  const password = req.body.password;

  if(!name || !password) {
    return res.status(422).send({error: 'You must provide name + password'});
  }

  User.findOne({name}, function(err, existingUser) {
    if(err) {
      return next(err);
    }

    if(existingUser) {
      return res.status(422).send({error: 'Name is in use'});
    }

    const user = new User({
      name,
      password
    });

    user.save(function(err) {
      if(err) { return next(err); }

      res.json({token: tokenForUser(user)});
    })
  });
}
