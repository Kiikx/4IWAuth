// Fonction à appeler pour déconnecter l'utilisateur
function logout () {
  // Envoie d'identifiants erronés pour écraser le cache du navigateur
  fetch('/admin-page', {
    headers: { Authorization: 'Basic logout:logout' }
  }).then(() => {
    window.location.href = '/register.html'
  })
}
