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
    password: String,
    role: String
};

const moviesSchema = {
    name: String,
    description: String,
    thumbnail: String,
    video: String
};

const commentSchema = {
    userName: String,
    userComment: String
}


const User = new mongoose.model("User", userSchema);
const Movie = new mongoose.model("Movies", moviesSchema);
const Comment = new mongoose.model("Comments", commentSchema);

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
                password: hashedPassword,
                role: 'admin'
            });
            const user = await newUser.save();
            const jwtToken = generateAccesstoken({ id: user.id, email: user.email, role: user.role });
            res.status(200).json({ message: "Success", token: jwtToken, email: user.email, role: user.role });
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
                const jwtToken = generateAccesstoken({ id: foundUser.id, email: foundUser.email, role: foundUser.role });
                res.status(200).json({ message: "Success", token: jwtToken, email: foundUser.email, role: foundUser.role });
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

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers["authorization"];
    const accessToken = authHeader && authHeader.split(" ")[1];
    if (!accessToken) {
        res.status(400).send("Required header is not specified.");
        return;
    }

    jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) {
            console.log(err);
            res.status(401).send("Unauthorized");
            return;
        }
        req.user = user;
        next();
    });
};

app.post('/movie/:id/addComment', authenticateToken, async (req, res, next) => {
    const userName = req.user;
    const comment = new Comment({ movieId: req.params.id, userName, userComment: req.body.userComment });
    const newComment = await comment.save();
    res.status(200).send(newComment);
});

app.post('/addMovie', authenticateToken, async (req, res, next) => {
    const movie = new Movie(req.body);
    await movie.save();
    res.status(200).send(movie);
});

app.get('/movies', async (req, res, next) => {
    const movies = await Movie.find({});
    res.status(200).send(movies);
});

const generateAccesstoken = (userId) => {
    return jwt.sign(userId, process.env.ACCESS_TOKEN_SECRET);
};

app.listen(9000, () => console.log('Server started listening at port 9000'));

