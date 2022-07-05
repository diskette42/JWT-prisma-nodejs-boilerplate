const express = require('express')
const { v4: uuidV4 } = require('uuid')
const { generateTokens, generateAccessToken } = require('../../utils/jwt')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
const {
  createUserByUsernameAndPassword,
  findUserByUsername,
  findUserById,
} = require('../users/users.service')
const {
  addRefreshTokenToWhitelist,
  findRefreshTokenById,
  deleteRefreshToken,
  revokeTokens,
} = require('./auth.service')
const { JsonWebTokenError } = require('jsonwebtoken')
const { hashToken } = require('../../utils/hashToken')

const router = express.Router()

router.post('/register', async (req, res, next) => {
  try {
    const { username, password } = req.body
    console.log(username)
    if (!username || !password) {
      res.status(400)
      throw new Error('Email and password are required')
    }
    const existingUser = await findUserByUsername(username)
    console.log(existingUser)
    if (existingUser) {
      res.status(400)
      throw new Error('User already exists')
    }

    const user = await createUserByUsernameAndPassword({ username, password })
    const jti = uuidV4()
    console.log({ jti })
    const { accessToken, refreshToken } = generateTokens(user, jti)
    res.json({
      accessToken,
      refreshToken,
    })
  } catch (err) {
    next(err)
  }
})

router.post('/login', async (req, res, next) => {
  try {
    const { username, password } = req.body
    if (!username || !password) {
      res.status(400)
      throw new Error('Email and password are required')
    }

    const existingUser = await findUserByUsername(username)

    if (!existingUser) {
      res.status(403)
      throw new Error('User does not exist')
    }

    const validPassword = await bcrypt.compare(password, existingUser.password)
    if (!validPassword) {
      res.status(403)
      throw new Error('Invalid password')
    }

    const jti = uuidV4()
    console.log({ jti })
    const { accessToken, refreshToken } = generateTokens(existingUser, jti)
    await addRefreshTokenToWhitelist({
      jti,
      refreshToken,
      userId: existingUser.id,
    })

    res.json({
      accessToken,
      refreshToken,
    })
  } catch (err) {
    next(err)
  }
})

router.post('/refreshToken', async (req, res, next) => {
  try {
    const { refreshToken } = req.body
    if (!refreshToken) {
      res.status(400)
      throw new Error('Refresh token is Missing')
    }

    const payload = await jwt.verify(
      refreshToken,
      process.env.JWT_REFRESH_SECRET,
    )

    const savedRefreshToken = await findRefreshTokenById(payload.jti)

    if (!savedRefreshToken || savedRefreshToken.revoked) {
      res.status(401)
      throw new Error('Unauthorized')
    }

    const hashedToken = hashToken(refreshToken)
    if (hashedToken != savedRefreshToken.hashedToken) {
      res.status(401)
      throw new Error('Unauthorized')
    }

    const user = await findUserById(payload.userId)
    if (!user) {
      res.status(401)
      throw new Error('Unauthorized')
    }

    await deleteRefreshToken(savedRefreshToken.id)
    const jti = uuidV4()
    const { accessToken, refreshToken: newRefreshToken } = generateTokens(
      user,
      jti,
    )
    // console.log({ accessToken, newRefreshToken, refreshToken })
    await addRefreshTokenToWhitelist({
      jti,
      refreshToken: newRefreshToken,
      userId: user.id,
    })
    res.json({
      message: accessToken,
      refreshToken: newRefreshToken,
    })
  } catch (err) {
    next(err)
  }
})

router.post('/refreshCheck', async (req, res, next) => {
  try {
    const { refreshToken } = req.body
    if (!refreshToken) {
      res.status(400)
      throw new Error('Refresh token is Missing')
    }

    const payload = await jwt.verify(
      refreshToken,
      process.env.JWT_REFRESH_SECRET,
    )
    console.log({ payload })
    const hashedToken = hashToken(refreshToken)
    console.log(hashedToken)
    res.json({
      hashToken: hashedToken,
      jwtPayload: payload,
    })
  } catch (err) {
    next(err)
  }
})

router.post('revokeRefreshTokens', async (req, res, next) => {
  try {
    const { userId } = req.body
    await revokeTokens(userId)
    res.json({ message: `Tokens revoked for user with id #${userId}` })
  } catch (err) {
    next(err)
  }
})

router.post('/accessTokenRefresh', async (req, res, next) => {
  try {
    const { userId, refreshToken } = req.body
    if (!userId) {
      res.status(400)
      throw new Error('UserId is required')
    }
    const existingUser = await findUserById(userId)
    if (!existingUser) {
      res.status(400)
      throw new Error('User does not exist')
    }
    const payload = await jwt.verify(
      refreshToken,
      process.env.JWT_REFRESH_SECRET,
    )
    if (payload.userId != existingUser.id) {
      res.status(400)
      throw new Error('Not the user RefreshToken')
    }
    const accessToken = await generateAccessToken(existingUser)
    res.json({ accessToken, message: 'Access token refreshed' })
  } catch (err) {
    next(err)
  }
})

module.exports = router
