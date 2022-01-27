// midleware to check if the user.roleId user is admin
const jwt = require('jsonwebtoken')
const createHttpError = require('http-errors')
const config = require('../config/config').development
const { splitToken } = require('../utilities/jwtUtilities')

const isAdmin = (req, res, next) => {
  const bearerToken = req.headers.authorization
  if (!bearerToken) {
    const httpError = createHttpError(401, 'No token provided')
    next(httpError)
  }
  const token = splitToken(bearerToken)

  jwt.verify(token, config.secret, (err, decoded) => {
    if (err) {
      const httpError = createHttpError(401, 'Failed to authenticate token')
      next(httpError)
    }
    // if (decoded.role === 'Admin') { // cant be 'role'.  it's the table name
    if (decoded.user.userRole === 'Admin') {
      next()
    } else {
      const httpError = createHttpError(401, 'Forbidden access')
      next(httpError)
    }
    return null
  })
  return null
}
module.exports = isAdmin
