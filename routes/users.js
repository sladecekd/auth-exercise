const {User, validate} = require('../models/users');
const mongoose = require('mongoose');
const _ = require('lodash');
const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');

mongoose.set('useCreateIndex', true);

router.post('/', async (req, res) => {
    const { error } = validate(req.body);
    if (error) return res.status(400).send(error.details[0].message);

    // Find if user with the email already exists
    let user = await User.findOne({
        email: req.body.email
    });

    // return bad request if exists
    if (user) return res.status(400).send('User already registred.');

    // Create a new user
    user = new User(_.pick(req.body, ['name', 'email', 'password']));
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(user.password , salt);
    await user.save();

    const token = user.generateAuthToken();
    res.header('x-auth-header', token).send(_.pick(user, ['_id', 'name', 'email']));
});

module.exports = router;
