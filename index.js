const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs');

const session = require('express-session'); // Sessions 1. import it



const UsersDB = require('./usersHelpers.js');


const server = express();

// Sessions 3. configure it here
const sessionConfig = {
    name: 'banana', // to change from the default name of 'sid'
    secret: 'This can be literally be anything! So make it a bit long for security', // have this on .env file for production
    cookie: {
        maxAge: 1000 * 60 * 15, // session length in milliseconds (this is for 15 mins)
        secure: false, // used over https only if true
    },
    httpOnly: true, // the user can't access the cookie from js using document.cookie if true
    resave: false,
    saveUninitialized: false, // laws against setting cookies automatically


};

server.use(helmet());
server.use(express.json());
server.use(cors());
server.use(session(sessionConfig)); // Sessions 2. let the server use it


server.post('/api/register', (req, res) => {
    
    let user = req.body;

    //generate hash from password
    const hash = bcrypt.hashSync(user.password, 15); // 2^n (rehashes)
    //override user.password with generated hash
    user.password = hash;

    UsersDB.add (user)
        .then(saved => {
            res.status(201).json(saved);
        })
        .catch(error => {
            res.status(500).json(error);
        });
});


server.post('/api/login', (req, res) => {
    let { username, password } = req.body;
  
    UsersDB.findBy({ username })
      .first()
      .then(user => {
        // check that passwords match
        if (user && bcrypt.compareSync(password, user.password)) {
            res.session.user = user; // Sessions 4. add this
          res.status(200).json({ message: `Welcome ${user.username}, you get a cookie!` });
        } else {
          res.status(401).json({ message: 'You Shall Not Pass!' });
        }
      })
      .catch(error => {
        res.status(500).json(error);
      });
  });


server.get('/api/users', async (req, res) => {
    try {
      const users = await UsersDB.find();
  
      res.json(users);
    } catch (error) {
      res.send(error);
    }
  });


const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n ***** Running on port ${port} ***** \n`));