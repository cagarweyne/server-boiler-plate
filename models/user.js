const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt-nodejs');

//Define the model
const userSchema = new Schema({
  email: {type: String, unique: true, lowercase: true},
  password: String
});

//on save hook, encrypt password
//before saving a model, run this function
userSchema.pre('save', function(next) {
  //set the user to apply the settings to
  const user = this; // user.email - user.password

  //use bycrypts genSalt method
  //generats salt then run callback
  bcrypt.genSalt(10, function(err, salt) {
    if(err) { next(err); }

    //use bycrypts hash method
    //hash (encrypt) the password using the salt
    bcrypt.hash(user.password, salt, null, function(err, hash) {
      if(err) { return next(next); }

      //overwite plain text password with hash
      user.password = hash;
      next();
    })
  })
});

userSchema.methods.comparePassword = function(candidatePassword, callback) {
  bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
    if(err) { return callback(err) }

    callback(null, isMatch)
  })
}

//Create the user class based on the model we have created
const ModelClass = mongoose.model('user', userSchema);

//export the model

module.exports = ModelClass;
