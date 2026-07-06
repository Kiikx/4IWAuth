require('dotenv').config()

const express = require('express')
const session = require('express-session')
const authRouter = require('./routes/auth')
const batcaveRouter = require('./routes/batcave')

const app = express()
const PORT = process.env.PORT || 3000
const SESSION_SECRET = process.env.SESSION_SECRET

if (!SESSION_SECRET) {
  throw new Error('SESSION_SECRET doit être défini dans le fichier .env')
}

app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(express.static('public'))

app.use(session({
  name: 'bat_identity',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'strict',
    maxAge: 1800000,
    secure: process.env.NODE_ENV === 'production'
  }
}))

app.use('/auth', authRouter)
app.use(batcaveRouter)

app.listen(PORT, () => {
  console.log(`Serveur démarré sur http://localhost:${PORT}`)
})
