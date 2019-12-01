const {User} = require('../models/users');
const mongoose = require('mongoose');
const _ = require('lodash');
const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const Joi = require('joi');

mongoose.set('useCreateIndex', true);

router.post('/', async (req, res) => {
    const { error } = validate(req.body);
    if (error) return res.status(400).send(error.details[0].message);

    // Find if user with the email already exists
    let user = await User.findOne({
        email: req.body.email
    });

    // Return bad request (for security reasons) if user does not exists
    if (!user) return res.status(400).send('Invalid email or password.');

    // Compare plain text password with hashed password from the DB
    const validPassword = await bcrypt.compare(req.body.password, user.password);
    if (!validPassword) return res.status(400).send('Invalid email or password.');

    const token = user.generateAuthToken();
    res.send(token);
});

function validate(req) {
    const schema = {
        email: Joi.string().min(5).max(255).required().email(),
        password: Joi.string().min(5).max(1024).required()
    };

    return Joi.validate(req, schema);
}

module.exports = router;
