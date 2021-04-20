const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const jwtsecret = require("../secrets"); // use this secret!
const Users = require('../users/users-model');
const bcrypt = require('bcryptjs');
const { default: jwtDecode } = require("jwt-decode");
const jwt = require('jsonwebtoken');

router.post("/register", validateRoleName, (req, res, next) => {
  let user = req.body;
  const hash = bcrypt.hashSync(user.password, 8);
  user.password = hash;

  Users.add(user)
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
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
});
function makeToken (user) {
  const payload = {
    subject: user.id,
    username: user.username,
    role_name: user.role_name
  }
  const options = {
    expiresIn: '24h'
  }
  return jwt.sign(payload, jwtsecret, options);
}
module.exports = router;
