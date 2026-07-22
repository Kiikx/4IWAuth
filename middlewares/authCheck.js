const jwt = require('jsonwebtoken')

const JWT_SECRET = process.env.JWT_SECRET || process.env.SESSION_SECRET

const isAuthenticated = (req, res, next) => {
  const authorizationHeader = req.get('Authorization') || ''
  const bearerToken = authorizationHeader.startsWith('Bearer ')
    ? authorizationHeader.slice(7)
    : null
  const token = req.cookies?.accessToken || bearerToken

  if (!JWT_SECRET) {
    return res.status(500).json({ error: 'JWT_SECRET ou SESSION_SECRET manquant' })
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET)
    req.user = {
      id: Number(payload.sub),
      username: payload.username
    }
    return next()
  } catch (err) {
    if (req.accepts('html')) {
      return res.status(401).send(`
        <!DOCTYPE html>
        <html lang="fr-FR">
          <head>
            <meta charset="UTF-8" />
            <meta http-equiv="refresh" content="1; url=/auth/login" />
            <title>Authentification requise</title>
          </head>
          <body>
            <p>Authentification requise. Redirection vers la page de connexion...</p>
            <a href="/auth/login">Se connecter</a>
          </body>
        </html>
      `)
    }

    return res.status(401).json({
      error: 'Authentification requise',
      redirect: '/auth/login'
    })
  }
}

module.exports = { isAuthenticated }
