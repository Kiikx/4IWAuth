const express = require('express')
const path = require('path')
const fs = require('fs')
const db = require('../db')
const { isAuthenticated } = require('../middlewares/authCheck')

const router = express.Router()
const batComputerPath = path.join(__dirname, '..', 'private', 'bat-computer.html')

router.use(isAuthenticated)

router.get(['/admin-page', '/admin-page.html'], (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'views', 'admin-page.html'))
})

router.get(['/bat-computer', '/bat-computer.html'], (req, res) => {
  const html = fs.readFileSync(batComputerPath, 'utf8')
  res.send(html.replace('Bienvenue...', `Bienvenue, Justicier ${req.session.user.username}`))
})

router.get('/api/secrets', (req, res) => {
  const secrets = [
    { name: 'Batarang', desc: 'Arme de jet', icon: 'fa-shuriken' },
    { name: 'Grappin', desc: "Câble d'escalade", icon: 'fa-arrow-up' },
    { name: 'Smoke Bomb', desc: 'Bombe fumigène', icon: 'fa-cloud' },
    { name: 'Batmobile', desc: 'Véhicule principal', icon: 'fa-car' }
  ]
  res.json(secrets)
})

router.get('/api/me', (req, res) => {
  res.json(req.session.user)
})

router.post('/api/reports', (req, res) => {
  const { mission_note } = req.body

  if (!mission_note || mission_note.trim() === '') {
    return res.status(400).send('La note de mission ne peut pas être vide.')
  }

  try {
    const insert = db.prepare(
      'INSERT INTO reports (user_id, mission_note) VALUES (?, ?)'
    )
    insert.run(req.session.user.id, mission_note)
    return res.status(201).json({ message: 'Rapport enregistré avec succès !' })
  } catch (err) {
    return res.status(500).send('Erreur lors de l\'enregistrement du rapport.')
  }
})

module.exports = router
