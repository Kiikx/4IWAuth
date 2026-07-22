const express = require('express')
const bcrypt = require('bcrypt')
const crypto = require('crypto')
const jwt = require('jsonwebtoken')
const db = require('../db')
const { isAuthenticated } = require('../middlewares/authCheck')

const router = express.Router()
const ACCESS_TOKEN_MAX_AGE = 15 * 60 * 1000
const REFRESH_TOKEN_MAX_AGE = 7 * 24 * 60 * 60 * 1000
const JWT_SECRET = process.env.JWT_SECRET || process.env.SESSION_SECRET

const cookieOptions = {
  httpOnly: true,
  sameSite: 'strict',
  secure: process.env.NODE_ENV === 'production'
}

const hashRefreshToken = token => crypto
  .createHash('sha256')
  .update(token)
  .digest('hex')

const createAccessToken = user => jwt.sign(
  { username: user.username },
  JWT_SECRET,
  {
    subject: String(user.id),
    expiresIn: '15m'
  }
)

const createRefreshToken = userId => {
  const token = crypto.randomBytes(48).toString('hex')
  const expiresAt = Date.now() + REFRESH_TOKEN_MAX_AGE

  db.prepare(
    'INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)'
  ).run(userId, hashRefreshToken(token), expiresAt)

  return token
}

const setAuthCookies = (res, user, refreshToken = null) => {
  const accessToken = createAccessToken(user)

  res.cookie('accessToken', accessToken, {
    ...cookieOptions,
    maxAge: ACCESS_TOKEN_MAX_AGE
  })

  if (refreshToken) {
    res.cookie('refreshToken', refreshToken, {
      ...cookieOptions,
      maxAge: REFRESH_TOKEN_MAX_AGE
    })
  }
}

const clearAuthCookies = res => {
  res.clearCookie('accessToken', cookieOptions)
  res.clearCookie('refreshToken', cookieOptions)
}

const validateRegistration = ({ username, password }) => {
  if (!username || typeof username !== 'string') {
    return "Le nom d'utilisateur est obligatoire."
  }

  if (!password || password.length < 8) {
    return 'Le mot de passe doit faire au moins 8 caractères.'
  }

  const cleanUsername = username.trim()

  if (!cleanUsername) {
    return "Le nom d'utilisateur ne peut pas être vide."
  }

  if (/\s/.test(cleanUsername)) {
    return "Le nom d'utilisateur ne doit pas contenir d'espaces."
  }

  return null
}

router.get('/login', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="fr-FR">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Connexion Batcave</title>
        <link
          href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css"
          rel="stylesheet"
          integrity="sha384-sRIl4kxILFvY47J16cr9ZwB07vP4J8+LH7qKQnuqkuIAvNWLzeN8tE5YBujZqJLB"
          crossorigin="anonymous"
        />
      </head>
      <body>
        <main class="container mt-5" style="max-width: 520px;">
          <h1>Connexion Batcave</h1>
          <form method="post" action="/auth/login" class="mt-4">
            <div class="mb-3">
              <label for="username" class="form-label">Nom d'utilisateur</label>
              <input id="username" name="username" type="text" class="form-control" required />
            </div>
            <div class="mb-3">
              <label for="password" class="form-label">Mot de passe</label>
              <input id="password" name="password" type="password" class="form-control" required />
            </div>
            <button type="submit" class="btn btn-primary">Se connecter</button>
            <a href="/register.html" class="btn btn-link">Créer un compte</a>
          </form>
        </main>
      </body>
    </html>
  `)
})

router.post('/login', async (req, res) => {
  const { username, password } = req.body
  const cleanUsername = typeof username === 'string' ? username.trim() : ''

  if (!cleanUsername || !password) {
    return res.status(400).send('Identifiants manquants')
  }

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(cleanUsername)
  const passwordMatches = user && await bcrypt.compare(password, user.password_hash)

  if (!passwordMatches) {
    return res.status(401).send('Identifiants invalides')
  }

  const refreshToken = createRefreshToken(user.id)
  setAuthCookies(res, user, refreshToken)
  return res.redirect('/bat-computer')
})

router.post('/register', async (req, res) => {
  const error = validateRegistration(req.body)

  if (error) {
    return res.status(400).send(error)
  }

  const cleanUsername = req.body.username.trim()
  const hash = await bcrypt.hash(req.body.password, 10)

  try {
    const insert = db.prepare(
      'INSERT INTO users (username, password_hash) VALUES (?, ?)'
    )
    insert.run(cleanUsername, hash)
    return res.status(201).send('Utilisateur créé avec succès !')
  } catch (err) {
    return res.status(409).send("Erreur : l'utilisateur existe déjà.")
  }
})

router.get('/logout', (req, res) => {
  const refreshToken = req.cookies?.refreshToken

  if (refreshToken) {
    db.prepare('DELETE FROM refresh_tokens WHERE token_hash = ?')
      .run(hashRefreshToken(refreshToken))
  }

  clearAuthCookies(res)
  return res.redirect('/auth/login')
})

router.post('/refresh', (req, res) => {
  const refreshToken = req.cookies?.refreshToken

  if (!refreshToken) {
    clearAuthCookies(res)
    return res.status(401).json({ error: 'Refresh token manquant' })
  }

  const storedToken = db.prepare(`
    SELECT refresh_tokens.*, users.username
    FROM refresh_tokens
    JOIN users ON users.id = refresh_tokens.user_id
    WHERE refresh_tokens.token_hash = ?
  `).get(hashRefreshToken(refreshToken))

  if (!storedToken || storedToken.expires_at <= Date.now()) {
    if (storedToken) {
      db.prepare('DELETE FROM refresh_tokens WHERE id = ?').run(storedToken.id)
    }

    clearAuthCookies(res)
    return res.status(401).json({ error: 'Refresh token invalide ou expire' })
  }

  setAuthCookies(res, {
    id: storedToken.user_id,
    username: storedToken.username
  })

  return res.json({ message: 'Access token renouvele' })
})

router.post('/change-password', isAuthenticated, async (req, res) => {
  const { oldPassword, newPassword } = req.body
  const strongPassword = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d]).{12,}$/

  if (!oldPassword || !newPassword) {
    return res.status(400).json({ error: 'Ancien et nouveau mot de passe requis' })
  }

  if (!strongPassword.test(newPassword)) {
    return res.status(400).json({
      error: 'Le nouveau mot de passe doit contenir au moins 12 caracteres, une majuscule, une minuscule, un chiffre et un caractere special.'
    })
  }

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id)
  const oldPasswordMatches = user && await bcrypt.compare(oldPassword, user.password_hash)

  if (!oldPasswordMatches) {
    return res.status(401).json({ error: 'Ancien mot de passe invalide' })
  }

  const hash = await bcrypt.hash(newPassword, 10)
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, req.user.id)

  return res.json({ message: 'Mot de passe modifie avec succes' })
})

module.exports = router
