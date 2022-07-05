const express = require('express')
const cors = require('cors')
const app = express()

const api = require('./api')

app.use(cors())
app.use(express.json())

app.get('/', (req, res) => {
  res.json({
    message: 'Hello World',
  })
})

app.use('/api/v1', api)

module.exports = app
