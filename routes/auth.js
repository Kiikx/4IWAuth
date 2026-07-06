const express = require('express')
const bcrypt = require('bcrypt')
const db = require('../db')

const router = express.Router()

const validateRegistration = ({ username, password }) => {
  if (!username || typeof username !== 'string') {
    return "Le nom d'utilisateur est obligatoire."
  }

  if (!password || password.length < 8) {
    return 'Le mot de passe doit faire au moins 8 caractères.'
  }

  const cleanUsername = username.trim()

  if (!cleanUsername) {
    return 'Le nom d\'utilisateur ne peut pas être vide.'
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

  req.session.regenerate(err => {
    if (err) {
      return res.status(500).send('Erreur lors de la création de session')
    }

    req.session.user = {
      id: user.id,
      username: user.username
    }

    req.session.save(saveErr => {
      if (saveErr) {
        return res.status(500).send('Erreur lors de la sauvegarde de session')
      }

      return res.redirect('/bat-computer')
    })
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

router.get('/logout', (req, res) => {
  req.session.destroy(err => {
    res.clearCookie('bat_identity')

    if (err) {
      return res.status(500).send('Erreur lors de la déconnexion')
    }

    return res.redirect('/auth/login')
  })
})

module.exports = router
