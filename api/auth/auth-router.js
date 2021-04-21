const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const router = require("express").Router()

const { checkUsernameExists, validateRoleName, checkUsernameUnique } = require('./auth-middleware')
const { add } = require('../users/users-model')
const { JWT_SECRET } = require("../secrets") // use this secret!

router.post("/register", validateRoleName, checkUsernameUnique, (req, res, next) => {
  const { username, password, role_name } = req.body

  const hash = bcrypt.hashSync(password, 12)

  add({
    username,
    role_name,
    password: hash
  })
    .then( newUser => {
      res.status(201).json(newUser)
    })
    .catch(next)

  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
})


router.post("/login", checkUsernameExists, (req, res, next) => {
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
})

// reason this is there is so I can call next
// from either login or register and send a token
// because normally when you register you sign in
// but that would fail tests in this case
router.use( (req, res) => {
  const { id, username, role_name } = req.user
  const payload = {
    subject: id,
    username,
    role_name
  }
  const options = {
    expiresIn: '1d'
  }
  const token = jwt.sign(payload, JWT_SECRET, options)
  res.status(200).json({ message: `${username} is back`, token})
})
module.exports = router
