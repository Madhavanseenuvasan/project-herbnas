const express = require('express');
const dotenv = require('dotenv');
const connectDB = require('./config/db');
const authRoutes = require('./routes/authRoutes')
const leadRoutes = require('./routes/leadRoutes')

dotenv.config();
connectDB();

const app = express();
app.use(express.json());

app.use('/api/users',authRoutes);
app.use('/api/leads',leadRoutes)

module.exports = app;
