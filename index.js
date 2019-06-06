
const express = require('express');
const knex = require('knex');
const knexConfig = require('./knexfile');
const cors = require('cors');
const bcrypt = require('bcryptjs');

const db = knex(knexConfig.development);

const server = express();

server.use(express.json());

server.post('/api/register', async (req, res) => {
  try {
    const user = req.body;
    user.password = await bcrypt.hash(user.password, 16);
    const returnedId = await db.insert(user).into('users');
    const dbEntry = await db.select().from('users').where({ id: returnedId }).first();

    res.status(201).json(dbEntry);
  } catch (err) {
    res.status(500).json({ error: err });
  }
})

server.post('/api/login', async (req, res) => {
  try {
    const user = req.body;
    const dbData = await db.select().from('users').where({ username: user.username }).first();

    if (dbData && await bcrypt.compare(user.password, dbData.password)) {
      res.json({ message: 'Logged in' });
    } else {
      res.status(401).json({ message: 'Invalid Credentials' });
    }
  } catch (err) {
    res.status(500).json({ error: err });
  }
})

server.get('/api/users', async (req, res) => {
  try {
    const loggedIn = req.headers['logged-in'];
    
    if (loggedIn) {
      const dbData = await db.select().from('users');
  
      res.json(dbData);
    } else {
      res.status(401).json({ message: 'You shall not pass!' });
    }
  } catch (err) {
    res.status(500).json({ error: err });
  }
})

const port = 4040;

server.listen(port, () => {
  console.log(`Listening on port ${port}`);
})