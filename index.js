require("dotenv").config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();

app.use(express.json());
app.use(cors());

const saltRounds = 10;

mongoose.connect("mongodb://localhost:27017/userDB", { useNewUrlParser: true, });

const userSchema = {
    email: String,
    password: String
};

const User = new mongoose.model("User", userSchema);

app.post('/register', async (req, res) => {
    try {
        const foundUser = await User.findOne({ email: req.body.email });
        if (foundUser) {
            res.status(200).json({ message: "User already exists" });
            return;
        } else {
            const hashedPassword = await bcrypt.hash(req.body.password, saltRounds);
            const newUser = new User({
                email: req.body.email,
                password: hashedPassword
            });
            const user = await newUser.save();
            const jwtToken = generateAccesstoken(user.id);
            res.status(200).json({ message: "Success", token: jwtToken });
            return;
        }
    } catch (err) {
        console.log(err);
        res.status(500).send({ message: "Error while registering user" });
        return;
    }
});

app.post('/login', async (req, res) => {
    const email = req.body.email;
    const password = req.body.password;
    try {
        const foundUser = await User.findOne({ email: email });
        if (foundUser) {
            const bcryptCompareRes = await bcrypt.compare(password, foundUser.password);
            if (bcryptCompareRes === true) {
                const jwtToken = generateAccesstoken(foundUser.id);
                res.status(200).json({ message: "Success", token: jwtToken });
                return;
            } else {
                res.status(200).json({ message: 'Incorrect user password' });
                return;
            }
        } else {
            res.status(200).json({ message: 'User not found' });
            return;
        }
    } catch (err) {
        res.status(500).json({ message: 'There is an error while logging in. Try back after some time' });
        return;
    }
});


const generateAccesstoken = (userId) => {
    return jwt.sign(userId, process.env.ACCESS_TOKEN_SECRET);
};

app.listen(9000, () => console.log('Server started listening at port 9000'));

