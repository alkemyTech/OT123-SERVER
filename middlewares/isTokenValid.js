const { verifyToken } = require('../utilities/jwtUtilities')

// eslint-disable-next-line consistent-return
async function isTokenValid(req, res, next) {
  const bearerToken = req.headers.authorization
  if (!bearerToken) {
    return res.status(401).send({ auth: false, message: 'No token provided' })
  }
  try {
    const decoded = await verifyToken(bearerToken)
    req.user = decoded.user
    next()
  } catch (error) {
    res.status(400).json({
      ok: false,
      msg: 'wrong token',
      error,
    })
  }
}

module.exports = isTokenValid
