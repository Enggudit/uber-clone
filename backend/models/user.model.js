const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Define the user schema
const userSchema = new mongoose.Schema({
    fullname: {
        firstname: {
            type: String,
            required: [true, 'First name is required'],
            minLength: [3, 'First name must be at least 3 characters long'],
        },
        lastname: {
            type: String,
            required: [true, 'Last name is required'],
            minLength: [3, 'Last name must be at least 3 characters long'],
        },
    },
    email: {
        type: String,
        required: [true, 'Email is required'],
        unique: true,
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        minLength: [8, 'Password must be at least 8 characters long'],
        select: false, // Prevents password from being returned in queries by default
    },
    socketId: {
        type: String,
    },
});

// Method to generate an auth token
userSchema.methods.generateAuthToken = function () {
    const token = jwt.sign({ _id: this._id }, process.env.JWT_SECRET);
    return token;
};

// Method to compare passwords
userSchema.methods.comparePassword = async function (password) {
    return await bcrypt.compare(password, this.password);
};

// Method to hash a password
userSchema.methods.hashPassword = async function (password) {
    return await bcrypt.hash(password, 10);
};

// Define and export the model
const userModel = mongoose.model('User', userSchema);
module.exports = userModel;
