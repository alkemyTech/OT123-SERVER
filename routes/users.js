const express = require('express')

const router = express.Router()
const { checkSchema } = require('express-validator')
const user = require('../controllers/user')
const userSchema = require('../schemas/userSchema')

// get all users.
router.get('/', user.findAll)

// register a new user.
router.post(
  '/register',
  checkSchema(userSchema),
  user.registerUser,
)

// login user
router.post('/login', user.loginUser)

// delete user
router.delete('/delete', user.deleteUser)

module.exports = router
