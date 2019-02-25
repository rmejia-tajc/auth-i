const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs');



const UsersDB = require('./usersHelpers.js');


const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());


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
          res.status(200).json({ message: `Welcome ${user.username}!` });
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