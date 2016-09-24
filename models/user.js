const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt-nodejs');

// Define our model
const userSchema = new Schema({
	// unique is a mongoose attribute that tells mongoose to enforce uniqueness in db emails
	// lowercase is a mongoose attribute that tells mongoose to convert all emails into lowercase (useful here so that joe@email.com == JOE@email.com)
	email: {type: String, unique: true, lowercase: true},
	password: String
});

// Before each save (on save hook), run this function (which encrypts password)
userSchema.pre('save', function(next){
	// the context of this function is the user model that called this function
	const user = this;
	// generate a salt and then run callback
	bcrypt.genSalt(10, function(err, salt){
		if(err){return next(err);}
		// hash (encrypt) our password using the salt
		bcrypt.hash(user.password, salt, null, function(err, hash){
			if(err){return next(err);}
			// overwrite plain text password with encrypted password
			user.password = hash;
			// go ahead and save the model (since this is on a pre-save hook)
			next();
		});
	})
});

// we can define for our schema any methods we would like the User class to have access to
// in this case, we add a comparePassword() for quickly comparing passwords + salt
userSchema.methods.comparePassword = function(candidatePassword, callback){
	// use bcrypt to compare the incoming candidate password+salt vs this.password (which is already salted)
	// `this` refers to the caller of this function, which would be that user object
	bcrypt.compare(candidatePassword, this.password, function(err, isMatch){
		if(err){return callback(err);}
		// isMatch will be true or false according to the comparison results
		callback(null, isMatch);
	});
}


// Create the model class
// we tell mongoose that the userSchema correlates to the mongo collection called 'user'
const ModelClass = mongoose.model('user', userSchema);

// Export the model
module.exports = ModelClass;