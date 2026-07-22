const loginForm = document.getElementById('login-form')
const verifyForm = document.getElementById('verify-2fa-form')
const setupPanel = document.getElementById('setup-2fa-panel')
const setupButton = document.getElementById('start-2fa-setup')
const setupResult = document.getElementById('setup-2fa-result')
const confirmForm = document.getElementById('confirm-2fa-form')
const message = document.getElementById('login-message')

let pendingUsername = ''
let pendingPassword = ''

const setMessage = (content, type = 'danger') => {
  message.innerHTML = `<div class="alert alert-${type}">${content}</div>`
}

loginForm.addEventListener('submit', async event => {
  event.preventDefault()
  pendingUsername = document.getElementById('username').value.trim()
  pendingPassword = document.getElementById('password').value

  const response = await fetch('/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: pendingUsername, password: pendingPassword })
  })
  const data = await response.json().catch(() => ({}))

  verifyForm.classList.add('d-none')
  setupPanel.classList.add('d-none')

  if (response.ok && data.requires2FA) {
    pendingUsername = data.username
    verifyForm.classList.remove('d-none')
    setMessage(data.message, 'info')
    return
  }

  if (response.status === 403 && data.requires2FASetup) {
    setupPanel.classList.remove('d-none')
    setMessage(data.error, 'warning')
    return
  }

  setMessage(data.error || 'Connexion impossible')
})

verifyForm.addEventListener('submit', async event => {
  event.preventDefault()
  const code = document.getElementById('totp-code').value.trim()

  const response = await fetch('/api/verify-2fa', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: pendingUsername, code })
  })
  const data = await response.json().catch(() => ({}))

  if (response.ok) {
    window.location.href = data.redirect || '/bat-computer'
    return
  }

  setMessage(data.error || 'Code 2FA invalide')
})

setupButton.addEventListener('click', async () => {
  const response = await fetch('/api/auth/setup-2fa', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: pendingUsername, password: pendingPassword })
  })
  const data = await response.json().catch(() => ({}))

  if (!response.ok) {
    setMessage(data.error || 'Initialisation 2FA impossible')
    return
  }

  setupResult.innerHTML = `
    <img src="${data.qrCode}" alt="QR code 2FA" class="img-fluid border rounded mb-3" />
    <p class="mb-1">Secret de secours :</p>
    <code>${data.secret}</code>
  `
  confirmForm.classList.remove('d-none')
  setMessage(data.message, 'info')
})

confirmForm.addEventListener('submit', async event => {
  event.preventDefault()
  const code = document.getElementById('setup-code').value.trim()

  const response = await fetch('/api/auth/confirm-2fa', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: pendingUsername, code })
  })
  const data = await response.json().catch(() => ({}))

  if (!response.ok) {
    setMessage(data.error || 'Activation 2FA impossible')
    return
  }

  setupPanel.classList.add('d-none')
  verifyForm.classList.remove('d-none')
  setMessage('2FA activee. Saisissez maintenant un code pour terminer la connexion.', 'success')
})
