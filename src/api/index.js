const express = require('express')
const auth = require('./auth/auth.router')
const user = require('./users/users.router')
const router = express.Router()

router.use('/auth', auth)

router.use('/user', user)

module.exports = router
