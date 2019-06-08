
const express = require('express');
const knex = require('knex');
const knexConfig = require('./knexfile');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const session = require('express-session');

const db = knex(knexConfig.development);

const server = express();

server.use(
  session({
    name: 'sessionCookie',
    secret: 'ooh a spooky secret!',
    cookie: {
      maxAge: 1000*60*60*24*7,
      secure: true,
    },
    httpOnly: true,
    resave: false,
    saveUninitialized: false
  })
)

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
      req.session.username = `${user.username}`;
      res.json({ message: 'Logged in' });
    } else {
      res.status(401).json({ message: 'Invalid Credentials' });
    }
  } catch (err) {
    res.status(500).json({ error: err });
  }
})

server.get('/api/users', protected, async (req, res) => {
  try {
    const dbData = await db.select().from('users');

    res.json(dbData);
  } catch (err) {
    res.status(500).json({ error: err });
  }
})

server.get('/api/logout', (req, res) => {
  if (req.session) {
    req.session.destroy(err => {
      if (err) {
        res.send('error logging out');
      } else {
        res.send('good bye');
      }
    });
  }
});

function protected(req, res, next) {
  if (req.session && req.session.username) {
    next();
  } else {
    res.status(401).json({ message: 'you shall not pass!' });
  }
}

const port = 4040;

server.listen(port, () => {
  console.log(`Listening on port ${port}`);
})