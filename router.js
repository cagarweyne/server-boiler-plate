const Authentication = require('./controllers/authentication');
const passportService = require('./services/passport');
const passport = require('passport');

const requireAuth = passport.authenticate('jwt', { session: false });
const requireSignin = passport.authenticate('local', {session: false});


module.exports = function(app) {
  app.get('/', requireAuth, function(req, res) {
    res.send({ hi: 'you have reached protected resource' });
  });

  //signin route - on success will get jwt token for future requests
  app.post('/signin', requireSignin, Authentication.signin);
  //sign up route
  app.post('/signup', Authentication.signup);
}
