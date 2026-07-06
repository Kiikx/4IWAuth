// Import des librairies et de la BDD
const express = require('express')
const bcrypt = require('bcrypt')
const db = require('./db')

// Créé du serveur Express
const app = express()
// Rend possible la lecture et l'écriture du JSON
app.use(express.json())
// Ouvre les fichiers frontend non protégés
app.use(express.static('public'))

// Lance le serveur en local, sur le port 3000
const PORT = 3000
app.listen(PORT, () => {
  console.log(`Serveur démarré sur http://localhost:${PORT}`)
})

app.post('/register', async (req, res) => {
  // Récupère les identifiants saisis par l'utilisateur
  const { username, password } = req.body

  if (!username || typeof username !== 'string') {
    return res.status(400).send("Le nom d'utilisateur est obligatoire.")
  }

  if (!password || password.length < 8) {
    return res.status(400).send('Le mot de passe doit faire au moins 8 caractères.')
  }

  const cleanUsername = username.trim()

  // Vérification que le username n'est pas vide après trim
  if (!cleanUsername) {
    return res.status(400).send('Le nom d\'utilisateur ne peut pas être vide.')
  }

  if (/\s/.test(cleanUsername)) {
    return res.status(400).send("Le nom d'utilisateur ne doit pas contenir d'espaces.")
  }

  // Hachage du mot de passe avant stockage !
  const hash = await bcrypt.hash(password, 10)

  try {
    // Requête SQL pour insérer le nouvel utilisateur en base
    const insert = db.prepare(
      'INSERT INTO users (username, password_hash) VALUES (?, ?)'
    )
    insert.run(cleanUsername, hash)
    res.status(201).send('Utilisateur créé avec succès !')
  } catch (err) {
    res.status(409).send("Erreur : l'utilisateur existe déjà.")
  }
})

const checkAuth = async (req, res, next) => {
  // Récupère l'en-tête pour la vérifier avant d'atteindre les routes protégées
  const authHeader = req.headers.authorization

  if (!authHeader || !authHeader.startsWith('Basic ')) {
    // Ajoute l'en-tête pour demander au navigateur d'ouvrir la fenêtre de connexion
    res.setHeader('WWW-Authenticate', 'Basic realm="Administration"')
    return res.status(401).send('Authentification requise')
  }
  // Décodage du Base64
  const base64 = authHeader.split(' ')[1]
  const [username, password] = Buffer.from(base64, 'base64')
    .toString()
    .split(':')

  // Vérification en BDD 
  const user = db
    .prepare('SELECT * FROM users WHERE username = ?')
    .get(username)
  // Comparaison des mots de passe avec bcrypt
  if (user && (await bcrypt.compare(password, user.password_hash))) {
    req.user = user // On conserve l'utilisateur dans la requête, si besoin
    next()
  } else {
    return res.status(401).send('Identifiants invalides')
  }
}

app.get(['/admin-page', '/admin-page.html'], checkAuth, (req, res) => {
  // La route sert uniquement le fichier HTML
  res.sendFile(__dirname + '/views/admin-page.html')
})

app.get(['/bat-computer', '/bat-computer.html'], checkAuth, (req, res) => {
  res.sendFile(__dirname + '/private/bat-computer.html')
})

app.get('/api/secrets', checkAuth, (req, res) => {
  const secrets = [
    { "name": "Batarang", "desc": "Arme de jet", "icon": "fa-shuriken" },
    { "name": "Grappin", "desc": "Câble d'escalade", "icon": "fa-arrow-up" },
    { "name": "Smoke Bomb", "desc": "Bombe fumigène", "icon": "fa-cloud" },
    { "name": "Batmobile", "desc": "Véhicule principal", "icon": "fa-car" }
  ]
  res.json(secrets)
})

app.get('/api/me', checkAuth, (req, res) => {
  res.json({
    id: req.user.id,
    username: req.user.username
  })
})

app.post('/api/reports', checkAuth, (req, res) => {
  const { mission_note } = req.body

  if (!mission_note || mission_note.trim() === '') {
    return res.status(400).send('La note de mission ne peut pas être vide.')
  }

  try {
    const insert = db.prepare(
      'INSERT INTO reports (user_id, mission_note) VALUES (?, ?)'
    )
    insert.run(req.user.id, mission_note)
    res.status(201).json({ message: 'Rapport enregistré avec succès !' })
  } catch (err) {
    res.status(500).send('Erreur lors de l\'enregistrement du rapport.')
  }
})

app.get('/logout', (req, res) => {
  res.setHeader('WWW-Authenticate', 'Basic realm="Administration"')
  res.status(401).send('Déconnecté')
})