const jwtsecret = require("../secrets");
const jwt = require('jsonwebtoken');
const {findBy} = require('../users/users-model');


const restricted = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) {
    res.status(401).json({message: 'Token required'});
  } else {
    jwt.verify(token, jwtsecret, (err, decoded) => {
      if (err) {
        res.status(401).json({message: 'Token invalid'});
      } else {
        req.decodedToken = decoded;
        next();
      }
    });
  }
};


const only = role_name => (req, res, next) => {
  const decodedTkn = req.decodedToken;
  if(decodedTkn.role_name !== role_name) {
    res.status(403).json({message: 'This is not for you'});
  } else {
    next();
  }
};


const checkUsernameExists = async (req, res, next) => {
  const {username} = req.body;
  const usersName = await findBy({username});
  if (usersName) {
    next();
  } else {
    res.status(401).json({message: 'Invalid credentials'});
  }
};


const validateRoleName = (req, res, next) => {
  const {role_name} = req.body;
  if (!role_name || !role_name.trim()) {
    req.role_name = 'student';
    next();
  } else if (role_name.trim() === 'admin') {
    next({status:  422, message: 'Role name can not be admin'});
  } else if (role_name.trim().length > 32) {
    next({status: 422, message: 'Role name can not be longer than 32 chars'});
  } else {
    req.role_name = role_name.trim()
    next();
  }
  /*
    If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.

    If role_name is missing from req.body, or if after trimming it is just an empty string,
    set req.role_name to be 'student' and allow the request to proceed.

    If role_name is 'admin' after trimming the string:
    status 422
    {
      "message": "Role name can not be admin"
    }

    If role_name is over 32 characters after trimming the string:
    status 422
    {
      "message": "Role name can not be longer than 32 chars"
    }
  */
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
};
