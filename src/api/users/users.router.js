const express = require('express')
const { isAuthenticated } = require('../../middleware')
const { findUserById } = require('./users.service')

const router = express.Router()

router.get('/profile', isAuthenticated, async (req, res, next) => {
  try {
    const { userId } = req.payload
    const user = await findUserById(userId)
    delete user.password
    res.json(user)
  } catch (err) {
    next(err)
  }
})

module.exports = router
