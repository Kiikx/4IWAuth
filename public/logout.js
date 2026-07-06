// Fonction à appeler pour déconnecter l'utilisateur
function logout () {
  // Appelle la route de logout pour forcer le navigateur à "oublier" les credentials
  fetch('/logout')
    .catch(() => {
      // Le fetch échouera parce qu'on reçoit une 401, c'est normal
    })
    .finally(() => {
      // Redirige vers la page d'inscription
      window.location.href = '/register.html'
    })
}
