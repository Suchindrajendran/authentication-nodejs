const express = require('express')
const path = require('path')
const {open} = require('sqlite')
const sqlite3 = require('sqlite3')
const bcrypt = require('bcrypt')
const app = express()
app.use(express.json())

const dbPath = path.join(__dirname, 'userData.db')
let db = null

const initializeDBAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    })
    app.listen(3000, () => {
      console.log('Server is running on http://localhost:3000/')
    })
  } catch (e) {
    console.log(`DB Error: ${e.message}`)
    process.exit(1)
  }
}

initializeDBAndServer()

app.post('/register', async (request, response) => {
  const {username, name, password, gender, location} = request.body
  const hashedPassword = await bcrypt.hash(password, 10)
  const userQuery = `SELECT * FROM user WHERE username = ?`
  const dbUser = await db.get(userQuery, [username])

  if (password.length < 5) {
    response.status(400).send('Password is too short')
  } else if (dbUser === undefined) {
    const createUserQuery = `
      INSERT INTO user (username, name, password, gender, location)
      VALUES (?, ?, ?, ?, ?)`
    await db.run(createUserQuery, [
      username,
      name,
      hashedPassword,
      gender,
      location,
    ])
    response.status(200).send('User created successfully')
  } else {
    response.status(400).send('User already exists')
  }
})

app.post('/login', async (request, response) => {
  const {username, password} = request.body
  const userQuery = `SELECT * FROM user WHERE username = ?`
  const dbUser = await db.get(userQuery, [username])

  if (dbUser === undefined) {
    response.status(400).send('Invalid user')
  } else {
    const isPasswordMatched = await bcrypt.compare(password, dbUser.password)
    if (isPasswordMatched) {
      response.status(200).send('Login success!')
    } else {
      response.status(400).send('Invalid password')
    }
  }
})

app.put('/change-password', async (request, response) => {
  const {username, currentPassword, newPassword} = request.body

  // Fetch user from database
  const userQuery = `SELECT * FROM user WHERE username = ?`
  const dbUser = await db.get(userQuery, [username])

  if (dbUser === undefined) {
    response.status(400)
    response.send('User not registered')
  } else {
    const isValidPassword = await bcrypt.compare(
      currentPassword,
      dbUser.password,
    )
    if (isValidPassword === true) {
      const lengthOfPassword = newPassword.length
      if (lengthOfPassword < 5) {
        response.status(400)
        response.send('Password is too short')
      } else {
        const encryptPassword = await bcrypt.hash(newPassword, 10)
        const updatePassword = `
        update user 
        set password = ?
        where username = ?`
        await db.run(updatePassword, [encryptPassword, username])
        response.status(200)
        response.send('Password updated')
      }
    } else {
      response.status(400)
      response.send('Invalid current Password')
    }
  }
})

module.exports = app
