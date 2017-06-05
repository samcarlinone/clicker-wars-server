const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt-nodejs');

//Define model
const userSchema = new Schema({
  name: {
    type: String,
    unique: true,
    lowercase: true
  },
  password: String
});

//On save hook for pwd hashing
userSchema.pre('save', function(next) {
  bcrypt.genSalt(10, (err, salt) => {
    if(err) { return next(err); }

    bcrypt.hash(this.password, salt, null, (err, hash) => {
      if(err) { return next(err); }

      this.password = hash;
      next();
    });
  });
});

userSchema.methods.comparePassword = function(candidatePassword, callback) {
  bcrypt.compare(candidatePassword, this.password, (err, isMatch) => {
    if(err) { return callback(err); }

    callback(null, isMatch);
  });
}

//Create model class
const ModelClass = mongoose.model('user', userSchema);

//Export model
module.exports = ModelClass;
