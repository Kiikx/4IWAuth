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
