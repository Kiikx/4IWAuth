# 4IWAuth - Systeme de securite de la Batcave

TP1 : implementation d un serveur Express protege par Basic Auth, avec mots de passe haches par Bcrypt et stockage SQLite.

## Prerequis

- Node.js
- npm

Les dependances principales sont :

- `express`
- `bcrypt`
- `better-sqlite3`
- `nodemon`

## Installation

```bash
npm install
```

## Lancement

```bash
npm start
```

Le serveur demarre sur :

```text
http://localhost:3000
```

En developpement, vous pouvez aussi utiliser :

```bash
npm run dev
```

## Parcours navigateur

1. Ouvrir `http://localhost:3000/register.html`.
2. Creer un utilisateur avec un mot de passe de 8 caracteres minimum.
3. Ouvrir `http://localhost:3000/bat-computer`.
4. Renseigner les identifiants dans la fenetre Basic Auth du navigateur.
5. La page affiche le message personnalise, le formulaire de rapport et l arsenal dynamique.

## Routes principales

| Methode | Route | Protection | Role |
| --- | --- | --- | --- |
| `POST` | `/register` | Publique | Inscription utilisateur |
| `GET` | `/bat-computer` | Basic Auth | Page privee Bat-Ordinateur |
| `GET` | `/api/me` | Basic Auth | Utilisateur connecte |
| `GET` | `/api/secrets` | Basic Auth | Liste des gadgets |
| `POST` | `/api/reports` | Basic Auth | Creation de note de mission |
| `GET` | `/logout` | Publique | Tentative de deconnexion Basic Auth |

## Validation phase 4

### Navigateur

```text
http://localhost:3000/bat-computer
```

### cURL

```bash
curl -u "votre_pseudo:votre_pass" http://localhost:3000/api/secrets
```

### Postman

- Methode : `GET`
- URL : `http://localhost:3000/api/secrets`
- Onglet `Auth`
- Type : `Basic Auth`
- Renseigner le username et le password

## Base de donnees

La base SQLite locale est `auth_demo.db`.

Tables creees automatiquement au lancement :

- `users` : comptes utilisateurs avec username unique et hash de mot de passe.
- `reports` : notes de mission liees a un utilisateur.

## Etat du TP

- Phase 1 : initialisation Node, dependances et SQLite terminee.
- Phase 2 : registre public termine.
- Phase 2.1 : robustesse du registre terminee.
- Phase 3 : Basic Auth et routes protegees terminees.
- Phase 3.1 : personnalisation et rapports termines.
- Phase 3.2 : arsenal dynamique termine.
- Phase 4 : validation manuelle a effectuer avec navigateur, Postman et cURL.

## TP2 - Sessions et badge Batcave

Le TP2 remplace l'authentification Basic Auth par un badge de session stocke dans un cookie signe.

### Configuration

Copier le fichier d'exemple puis adapter la cle de session :

```bash
cp .env.example .env
```

Variables attendues :

```text
PORT=3000
SESSION_SECRET=une_cle_longue_et_aleatoire
```

Le cookie de session est configure avec :

- nom `bat_identity` ;
- `httpOnly: true` ;
- `sameSite: 'strict'` ;
- expiration apres 30 minutes.

### Parcours TP2

1. Demarrer le serveur :

```bash
npm start
```

2. Creer un compte si necessaire :

```text
http://localhost:3000/register.html
```

3. Ouvrir la page de connexion :

```text
http://localhost:3000/auth/login
```

4. Une fois connecte, le serveur cree une session et redirige vers :

```text
http://localhost:3000/bat-computer
```

5. La deconnexion propre se fait via :

```text
http://localhost:3000/auth/logout
```

### Structure TP2

- `server.js` : point d'entree Express, configuration session et montage des routeurs.
- `routes/auth.js` : login, traitement de login, inscription et logout.
- `routes/batcave.js` : routes protegees de la Batcave et API internes.
- `middlewares/authCheck.js` : verification de `req.session.user`.

### Verification rapide

```bash
npm test
```

Le test verifie la syntaxe du serveur, de la base, des routeurs et du middleware.
