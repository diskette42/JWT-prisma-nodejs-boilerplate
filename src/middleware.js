const jwt = require('jsonwebtoken')

function isAuthenticated(req, res, next) {
  const { authorization } = req.headers

  if (!authorization) {
    res.status(401)
    throw new Error('No authorization')
  }
  try {
    const token = authorization.split('Bearer ')[1]
    const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET)
    req.payload = payload
  } catch (err) {
    res.status(401)
    console.log(err)
    if (err.name === 'TokenExpiredError') {
      throw new Error(err.name)
    }
    throw new Error('Un-Authorized')
  }
  return next()
}

module.exports = {
  isAuthenticated,
}
