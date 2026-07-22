const express = require('express')
const bcrypt = require('bcrypt')
const crypto = require('crypto')
const jwt = require('jsonwebtoken')
const QRCode = require('qrcode')
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

const normalizeTotpCode = code => String(code || '').replace(/\D/g, '')

const generateTotpSecret = () => {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const randomBytes = crypto.randomBytes(20)

  return Array.from(randomBytes, byte => alphabet[byte % alphabet.length]).join('')
}

const createTotpUri = (username, secret) => {
  const label = encodeURIComponent(`Batcave:${username}`)
  const issuer = encodeURIComponent('Batcave')

  return `otpauth://totp/${label}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`
}

const decodeBase32 = secret => {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const cleanSecret = String(secret || '').replace(/=+$/g, '').replace(/\s/g, '').toUpperCase()
  let bits = ''
  const bytes = []

  for (const char of cleanSecret) {
    const value = alphabet.indexOf(char)

    if (value === -1) {
      return null
    }

    bits += value.toString(2).padStart(5, '0')
  }

  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2))
  }

  return Buffer.from(bytes)
}

const generateTotpCode = (secret, step = Math.floor(Date.now() / 30000)) => {
  const key = decodeBase32(secret)

  if (!key) {
    return null
  }

  const counter = Buffer.alloc(8)
  counter.writeUInt32BE(Math.floor(step / 0x100000000), 0)
  counter.writeUInt32BE(step >>> 0, 4)

  const hmac = crypto.createHmac('sha1', key).update(counter).digest()
  const offset = hmac[hmac.length - 1] & 0xf
  const binary = ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff)

  return String(binary % 1000000).padStart(6, '0')
}

const validateTotp = (code, secret) => {
  const cleanCode = normalizeTotpCode(code)
  const currentStep = Math.floor(Date.now() / 30000)

  if (cleanCode.length !== 6) {
    return false
  }

  for (let window = -2; window <= 2; window++) {
    if (generateTotpCode(secret, currentStep + window) === cleanCode) {
      return true
    }
  }

  return false
}

const totpError = "Code 2FA invalide ou expire. Verifiez que l'heure du telephone et du serveur est synchronisee."

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
        <main class="container mt-5" style="max-width: 560px;">
          <h1>Connexion Batcave</h1>
          <form id="login-form" class="mt-4">
            <div class="mb-3">
              <label for="username" class="form-label">Nom d'utilisateur</label>
              <input id="username" name="username" type="text" class="form-control" required />
            </div>
            <div class="mb-3">
              <label for="password" class="form-label">Mot de passe</label>
              <input id="password" name="password" type="password" class="form-control" required />
            </div>
            <button type="submit" class="btn btn-primary">Continuer</button>
            <a href="/register.html" class="btn btn-link">Créer un compte</a>
          </form>

          <form id="verify-2fa-form" class="mt-4 d-none">
            <div class="mb-3">
              <label for="totp-code" class="form-label">Code 2FA</label>
              <input id="totp-code" type="text" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" class="form-control" required />
            </div>
            <button type="submit" class="btn btn-success">Valider la connexion</button>
          </form>

          <section id="setup-2fa-panel" class="mt-4 d-none">
            <div class="alert alert-warning">Activez la 2FA avant de terminer la connexion.</div>
            <button id="start-2fa-setup" type="button" class="btn btn-warning">Generer le QR code</button>
            <div id="setup-2fa-result" class="mt-3"></div>
            <form id="confirm-2fa-form" class="mt-3 d-none">
              <div class="mb-3">
                <label for="setup-code" class="form-label">Premier code 2FA</label>
                <input id="setup-code" type="text" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" class="form-control" required />
              </div>
              <button type="submit" class="btn btn-success">Activer la 2FA</button>
            </form>
          </section>

          <div id="login-message" class="mt-3"></div>
        </main>
        <script src="/login.js"></script>
      </body>
    </html>
  `)
})

router.post('/login', async (req, res) => {
  const { username, password } = req.body
  const cleanUsername = typeof username === 'string' ? username.trim() : ''

  if (!cleanUsername || !password) {
    return res.status(400).json({ error: 'Identifiants manquants' })
  }

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(cleanUsername)
  const passwordMatches = user && await bcrypt.compare(password, user.password_hash)

  if (!passwordMatches) {
    return res.status(401).json({ error: 'Identifiants invalides' })
  }

  if (!user.two_factor_enabled) {
    clearAuthCookies(res)
    return res.status(403).json({
      error: 'Activation 2FA obligatoire avant connexion complete',
      requires2FASetup: true
    })
  }

  return res.json({
    requires2FA: true,
    username: user.username,
    message: 'Code 2FA requis pour terminer la connexion'
  })
})

router.post('/verify-2fa', (req, res) => {
  const { username, code } = req.body
  const cleanUsername = typeof username === 'string' ? username.trim() : ''

  if (!cleanUsername || normalizeTotpCode(code).length !== 6) {
    return res.status(400).json({ error: 'Nom utilisateur et code 2FA a 6 chiffres requis' })
  }

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(cleanUsername)

  if (!user || !user.two_factor_enabled || !user.two_factor_secret) {
    clearAuthCookies(res)
    return res.status(401).json({ error: 'Double authentification indisponible' })
  }

  const isValid = validateTotp(code, user.two_factor_secret)

  if (!isValid) {
    clearAuthCookies(res)
    return res.status(401).json({ error: totpError })
  }

  const refreshToken = createRefreshToken(user.id)
  setAuthCookies(res, user, refreshToken)

  return res.json({
    message: 'Connexion validee',
    redirect: '/bat-computer'
  })
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

const getFirstFactorUser = async (req) => {
  if (req.cookies?.accessToken) {
    try {
      const payload = jwt.verify(req.cookies.accessToken, JWT_SECRET)
      const user = db.prepare('SELECT * FROM users WHERE id = ?').get(Number(payload.sub))
      if (user) {
        return user
      }
    } catch (err) {}
  }

  const cleanUsername = typeof req.body.username === 'string' ? req.body.username.trim() : ''

  if (!cleanUsername || !req.body.password) {
    return null
  }

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(cleanUsername)
  const passwordMatches = user && await bcrypt.compare(req.body.password, user.password_hash)

  return passwordMatches ? user : null
}

router.post('/setup-2fa', async (req, res) => {
  const user = await getFirstFactorUser(req)

  if (!user) {
    return res.status(401).json({ error: 'Premier facteur invalide' })
  }

  const secret = generateTotpSecret()
  const otpauthUrl = createTotpUri(user.username, secret)

  db.prepare('UPDATE users SET two_factor_secret = ?, two_factor_enabled = 0 WHERE id = ?')
    .run(secret, user.id)

  const qrCode = await QRCode.toDataURL(otpauthUrl)

  return res.json({
    qrCode,
    secret,
    username: user.username,
    message: 'Scannez ce QR code puis confirmez le premier code TOTP.'
  })
})

router.post('/confirm-2fa', (req, res) => {
  const { code, username } = req.body
  const cleanUsername = typeof username === 'string' ? username.trim() : ''

  if (!cleanUsername || normalizeTotpCode(code).length !== 6) {
    return res.status(400).json({ error: 'Nom utilisateur et code TOTP a 6 chiffres requis' })
  }

  const user = db.prepare('SELECT id, two_factor_secret FROM users WHERE username = ?').get(cleanUsername)

  if (!user || !user.two_factor_secret) {
    return res.status(400).json({ error: 'Initialisation 2FA requise' })
  }

  const isValid = validateTotp(code, user.two_factor_secret)

  if (!isValid) {
    return res.status(401).json({ error: totpError })
  }

  db.prepare('UPDATE users SET two_factor_enabled = 1 WHERE id = ?').run(user.id)

  return res.json({ message: 'Double authentification activee avec succes' })
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
