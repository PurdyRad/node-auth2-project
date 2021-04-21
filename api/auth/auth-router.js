const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const jwtsecret = require("../secrets");
const Users = require('../users/users-model');
const bcrypt = require('bcryptjs');
const { default: jwtDecode } = require("jwt-decode");
const jwt = require('jsonwebtoken');

router.post("/register", validateRoleName, (req, res, next) => {
  const { username, password } = req.body;
  const { role_name } = req;
  const hash = bcrypt.hashSync(password, 8);
  // user.password = hash;

  Users.add({ username, password: hash, role_name })
  .then(newUser => {
    res.status(201).json(newUser);
  })
  .catch(next); 
});

router.post("/login", checkUsernameExists, (req, res, next) => {
  let {username, password} = req.body;
  Users.findBy({username})
  .then(([user]) => {
    if (user && bcrypt.compareSync(password, user.password)) {
      const token = makeToken(user);
      res.status(200).json({
        message: `${user.username} is back!`,
        token
      });
    } else {
      res.status(401).json({message: 'Invalid Credentials'});
    }
  })
  .catch(next);
});

function makeToken (user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name
  }
  const options = {
    expiresIn: '24h'
  }
  return jwt.sign(payload, jwtsecret, options);
}

module.exports = router;
