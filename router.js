const Authentication = require('./controllers/authentication');
const passportService = require('./services/passport');
const passport = require('passport');

// router middlewear using passport jwt strategy
// by default, passport will try to create a cookie session, but since we are using jwt we set session to false
// `local` will be for checking email+password on initial login
const requireSignin = passport.authenticate('local', {session: false})
// `jwt` is for all auth after initial login
const requireAuth = passport.authenticate('jwt', {session: false});

module.exports = function(app){

	// req = request coming in from client
	// res = response that is sent back to client
	// next = error handling
	/*app.get('/', function(req, res, next){
		res.send(["working fine", "waterbottle"]);
	});*/

	// follow this format for any protected route
	// aka use the requireAuth middleware
	app.get('/', requireAuth, function(req, res){
		res.send({hi:'there'});
	});
	// we force all requests coming into /signin to first go through the requireSignin local strategy (middleware), before going to the Authentication controller for signin
	app.post('/signin', requireSignin, Authentication.signin);
	app.post('/signup', Authentication.signup);

}