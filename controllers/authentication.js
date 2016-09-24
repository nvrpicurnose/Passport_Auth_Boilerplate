const User = require('../models/user');
const jwt = require('jwt-simple');
const config = require('../config');

// private function not exported
function tokenForUser(user){
	const timestamp = new Date().getTime();
	return jwt.encode({ 
		// jwt (json web token) by convention has a sub (subject) property to describe who this token belongs to
		sub: user.id,
		// jwt (json web token) also by convention has a iat (issued at time) property to describe when the token was made/issued
		iat: timestamp
	}, config.secret);
}

exports.signin = function(req, res, next){
	// User has already had their email and password auth'd
	// we just need to give them a token by passing in the user to the tokenForUser token generator
	res.send({token: tokenForUser(req.user)});
}

exports.signup = function(req, res, next){
	const email = req.body.email;
	const password = req.body.password;

	// check that the request has an email and password
	if(!email || !password){
		return res.status(422).send({error:"You must provide email and password"});
	}

	// See if a user with a given email exists
	User.findOne({email: email}, function(err, existingUser){
		if(err){return next(err);}
		// if a user with this email does exist, we will return an error on request
		if(existingUser){
			// status() sets the error code (eg. 404 Not Found)
			// Errorcode 402 Unprocessable Entity
			return res.status(402).send({error: "Email is in use"});
		}
		// If a user does not exist, create and save new user
		// const user is only a variable, it has not yet saved to the db
		const user = new User({
			email: email,
			password: password
		});
		// save() actually saves the new user to the db
		// pass in a callback indicating the user was created
		user.save(function(err){
			if(err){return next(err);}
			// Respond to request indicating the user was created
			res.json({token: tokenForUser(user)});
		});
	});
}