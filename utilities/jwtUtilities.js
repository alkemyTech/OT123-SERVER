const jwt = require('jsonwebtoken')
const config = require('../config/config').development

const generateToken = (user) => {
  const payload = { user }

  const token = jwt.sign(payload, config.secret, {
    expiresIn: '7d',
  })
  return token
}

const splitToken = (bearerToken) => {
  // I separate the bearer from the token using split
  const TokenArray = bearerToken.split(' ')
  return TokenArray[1]
}

const verifyToken = (bearerToken) => {
  const token = splitToken(bearerToken)
  const decodedToken = jwt.verify(token, config.secret)
  if (!decodedToken) {
    throw new Error('Invalid token')
  }
  return decodedToken
}

module.exports = { generateToken, verifyToken, splitToken }
