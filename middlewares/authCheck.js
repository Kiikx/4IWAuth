const isAuthenticated = (req, res, next) => {
  if (req.session && req.session.user) {
    return next()
  }

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

module.exports = { isAuthenticated }
