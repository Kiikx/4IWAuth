const redirectToLogin = () => {
  window.location.href = '/auth/login'
}

const apiFetch = async (url, options = {}) => {
  const response = await fetch(url, options)

  if (response.status !== 401) {
    return response
  }

  console.info('Access token expire, tentative de rafraichissement...')
  const refreshResponse = await fetch('/api/auth/refresh', {
    method: 'POST'
  })

  if (!refreshResponse.ok) {
    redirectToLogin()
    throw new Error('Refresh token invalide')
  }

  console.info('Access token renouvele, rejeu de la requete initiale.')
  return fetch(url, options)
}

fetch('/api/me')
  .then(response => response.json())
  .then(data => {
    document.getElementById('welcome-message').textContent = `Bienvenue, Justicier ${data.username}`
  })
  .catch(error => {
    console.error('Erreur:', error)
    document.getElementById('welcome-message').textContent = 'Erreur lors du chargement'
  })

document.getElementById('report-form').addEventListener('submit', async (e) => {
  e.preventDefault()
  const missionNote = document.getElementById('mission-note').value

  try {
    const response = await apiFetch('/api/reports', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ mission_note: missionNote })
    })

    const messageDiv = document.getElementById('message')
    if (response.ok) {
      messageDiv.innerHTML = '<div class="alert alert-success">Rapport enregistré avec succès !</div>'
      document.getElementById('mission-note').value = ''
    } else {
      messageDiv.innerHTML = `<div class="alert alert-danger">Erreur lors de l'enregistrement.</div>`
    }
  } catch (error) {
    console.error('Erreur:', error)
    document.getElementById('message').innerHTML = '<div class="alert alert-danger">Erreur réseau</div>'
  }
})

document.getElementById('password-form').addEventListener('submit', async (e) => {
  e.preventDefault()
  const oldPassword = document.getElementById('old-password').value
  const newPassword = document.getElementById('new-password').value
  const messageDiv = document.getElementById('password-message')

  try {
    const response = await apiFetch('/api/auth/change-password', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ oldPassword, newPassword })
    })
    const data = await response.json().catch(() => ({}))

    if (response.ok) {
      messageDiv.innerHTML = '<div class="alert alert-success">Mot de passe modifié.</div>'
      document.getElementById('password-form').reset()
    } else {
      messageDiv.innerHTML = `<div class="alert alert-danger">${data.error || 'Modification impossible.'}</div>`
    }
  } catch (error) {
    console.error('Erreur:', error)
    messageDiv.innerHTML = '<div class="alert alert-danger">Erreur réseau</div>'
  }
})

const createSecretCard = secret => {
  const column = document.createElement('div')
  column.className = 'col-sm-6 col-lg-3'
  column.innerHTML = '<article class="card h-100"><div class="card-body"><span class="badge text-bg-dark mb-3"></span><h3 class="h5 card-title"></h3><p class="card-text"></p></div></article>'
  column.querySelector('span').textContent = secret.icon
  column.querySelector('h3').textContent = secret.name
  column.querySelector('p').textContent = secret.desc
  return column
}

const loadSecrets = async () => {
  const messageDiv = document.getElementById('arsenal-message')
  const grid = document.getElementById('arsenal-grid')

  try {
    const response = await apiFetch('/api/secrets')

    if (!response.ok) {
      messageDiv.className = 'alert alert-danger'
      messageDiv.textContent = "Impossible de charger l'arsenal."
      return
    }

    const secrets = await response.json()
    grid.innerHTML = ''
    secrets.forEach(secret => {
      grid.appendChild(createSecretCard(secret))
    })
    messageDiv.remove()
  } catch (error) {
    console.error('Erreur:', error)
    messageDiv.className = 'alert alert-danger'
    messageDiv.textContent = 'Erreur réseau'
  }
}

loadSecrets()

const setupDashboard2FAButton = document.getElementById('dashboard-setup-2fa')
const dashboard2FAResult = document.getElementById('dashboard-2fa-result')
const dashboardConfirm2FAForm = document.getElementById('dashboard-confirm-2fa')

if (setupDashboard2FAButton && dashboardConfirm2FAForm) {
  setupDashboard2FAButton.addEventListener('click', async () => {
    const response = await apiFetch('/api/auth/setup-2fa', { method: 'POST' })
    const data = await response.json().catch(() => ({}))

    if (!response.ok) {
      dashboard2FAResult.innerHTML = `<div class="alert alert-danger">${data.error || 'Initialisation 2FA impossible.'}</div>`
      return
    }

    dashboard2FAResult.innerHTML = `
      <img src="${data.qrCode}" alt="QR code 2FA" class="img-fluid border rounded mb-3" />
      <p class="mb-1">Secret de secours :</p>
      <code>${data.secret}</code>
    `
    dashboardConfirm2FAForm.classList.remove('d-none')
  })

  dashboardConfirm2FAForm.addEventListener('submit', async event => {
    event.preventDefault()
    const code = document.getElementById('dashboard-2fa-code').value.replace(/\D/g, '')
    const meResponse = await apiFetch('/api/me')
    const me = await meResponse.json()

    const response = await apiFetch('/api/auth/confirm-2fa', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: me.username, code })
    })
    const data = await response.json().catch(() => ({}))

    if (response.ok) {
      dashboard2FAResult.innerHTML = '<div class="alert alert-success">Double authentification activee.</div>'
      dashboardConfirm2FAForm.reset()
      dashboardConfirm2FAForm.classList.add('d-none')
      return
    }

    dashboard2FAResult.innerHTML = `<div class="alert alert-danger">${data.error || 'Activation 2FA impossible.'}</div>`
  })
}
