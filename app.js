const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const express = require('express');
const rateLimit = require('express-rate-limit');
const userRouter = require('./routes/userRoutes');
const app = express();

app.use(express.json());

app.use(helmet());
app.use(mongoSanitize());

const limiter = rateLimit({
    max: 100,
    windowMs: 60 * 60 * 1000,
    message: 'Too many requests from this IP, please try again in an hour!'
});
app.use('/users', limiter);

app.use('/users', userRouter);
module.exports = app;