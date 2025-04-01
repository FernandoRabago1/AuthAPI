const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');

const authRoutes = require('./routes/auth.routes');
const userRoutes = require('./routes/user.routes');
const config = require('./config/config');

const app = express();

app.use(cors({
  origin: config.frontendOrigin,
  credentials: true
}));
app.use(cookieParser());
app.use(express.json());


app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);

app.get('/', (req, res) => {
  res.send('REST API Authentication and Authorization (Cookies + Redis, Rate Limit)');
});

module.exports = app;
