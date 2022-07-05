const bcrypt = require('bcrypt')
const { db } = require('../../utils/db')

function findUserByUsername(username) {
  console.log({ username })
  return db.user.findUnique({
    where: {
      username,
    },
  })
}

function createUserByUsernameAndPassword(user) {
  user.password = bcrypt.hashSync(user.password, 12)
  return db.user.create({
    data: user,
  })
}

function findUserById(id) {
  return db.user.findUnique({
    where: {
      id,
    },
  })
}

module.exports = {
  findUserByUsername,
  createUserByUsernameAndPassword,
  findUserById,
}
