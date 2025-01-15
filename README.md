 # Mon Application Flask

## Prérequis

- Python 3.12
- MySQL
- git

## Installation

1. Clonez ce dépôt sur votre machine locale :
   
```bash
git clone https://github.com/Waazor/tphckr.git
cd tphckr
```

2. Créez un environnement virutel

```bash
python -m venv venv
venv\Scripts\activate
```

3. Installez les dépendances

```bash
pip install -r requirements.txt
```

4. Créez un fichier ".env" et placez y les variables d'environnement requises

5. Créez une base de données appelé **tp_api** avec des tables **users** et **logs**

Se connecter au server Mysql :

```bash
mysql -u [username] -p
```

Créer une base de données **tp_api** :

```bash
CREATE DATABASE tp_api;
USE tp_api;
```

Importer les tables via le sql suivant : 

```bash
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL,
    created_at DATETIME NOT NULL
);

CREATE TABLE logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    endpoint VARCHAR(255) NOT NULL,
    method VARCHAR(10) NOT NULL,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status_code INT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

INSERT INTO users (username, password, role, created_at)
VALUES ('admin', '$2b$12$Iol.UFx9Gu9NkSu1kdKWB.V2VWA9DO9rdrFiPu2F7k7ecZJENR9Xa', 'admin', NOW());
```

Quitter mysql :

```bash
EXIT;
```

6. Lancez l'API

```bash
flask run
```

## Utilisation 

## Endpoints disponibles

### Authentification
Le login doit être la première requête exécutée, car elle permet d'obtenir le token JWT utile pour le mettre dans les autres requêtes validant l'identité de l'utilisateur, elle se met soit comme :
```bash
curl -X GET http://<votre-api>/protected-resource \
-H "Authorization: Bearer <votre-token-JWT>"
```
ou dans le bouton en haut à droite du Flasgger sous le même format ```Bearer <votre-token-JWT>```
#### **Login**
**URL**: `/login`  
**Méthode**: `POST`  
**Description**: Authentifie un utilisateur et retourne un token JWT.  
**Exemple de requête**:
```json
{
  "username": "admin",
  "password": "your_password"
}
```
**Exemple de réponse**:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6..."
}
```

---

### Gestion des utilisateurs (Admin uniquement)

#### **Créer un utilisateur**
**URL**: `/create-user`  
**Méthode**: `POST`  
**Description**: Crée un nouvel utilisateur.  
**Requiert un rôle admin.**  
**Exemple de requête**:
```json
{
  "username": "new_user",
  "password": "secure_password",
  "role": "good_guy"
}
```
**Exemple de réponse**:
```json
{
  "message": "Utilisateur créé avec succès"
}
```

#### **Supprimer un utilisateur**
**URL**: `/users/<user_id>`  
**Méthode**: `DELETE`  
**Description**: Supprime un utilisateur en fonction de son ID.  
**Exemple de réponse**:
```json
{
  "message": "Utilisateur avec l'ID 1 supprimé avec succès"
}
```

#### **Lister tous les utilisateurs**
**URL**: `/users`  
**Méthode**: `GET`  
**Description**: Retourne une liste de tous les utilisateurs.  
**Exemple de réponse**:
```json
[
  {
    "id": 1,
    "username": "admin",
    "role": "admin",
    "created_at": "2022-01-01T00:00:00Z"
  }
]
```

---

### Journaux (Logs) - Admin uniquement

#### **Lister tous les logs**
**URL**: `/logs`  
**Méthode**: `GET`  
**Description**: Retourne les logs de toutes les requêtes effectuées.  
**Exemple de réponse**:
```json
[
  {
    "id": 1,
    "user_id": 1,
    "endpoint": "/users",
    "method": "GET",
    "status_code": 200,
    "timestamp": "2022-01-01T00:00:00Z"
  }
]
```

#### **Lister les logs par utilisateur**
**URL**: `/logs/<user_id>`  
**Méthode**: `GET`  
**Description**: Retourne les logs pour un utilisateur spécifique.  

---

### Générations diverses

#### **Générer un mot de passe sécurisé**
**URL**: `/create-password/<taille>`  
**Méthode**: `GET`  
**Description**: Génère un mot de passe sécurisé d'une longueur minimale de 6 caractères.  
**Exemple de réponse**:
```json
{
  "password": "a7$bG1k*Qw"
}
```

#### **Créer une fausse identité**
**URL**: `/create-fake-identity`  
**Méthode**: `GET`  
**Description**: Génère une fausse identité avec un nom, un email, une adresse et un numéro de téléphone.  
**Exemple de réponse**:
```json
{
  "name": "John Doe",
  "email": "john.doe@example.com",
  "address": "123 Main St, Anytown, USA",
  "phone": "+123456789"
}
```

#### **Générer une image aléatoire**
**URL**: `/create-person`  
**Méthode**: `GET`  
**Description**: Retourne une image générée aléatoirement.  
**Exemple de réponse**: Une image binaire dans le corps de la réponse.

---

### Vérifications et recherches

#### **Vérifier un mot de passe**
**URL**: `/verif-password/<password>`  
**Méthode**: `GET`  
**Description**: Vérifie si un mot de passe donné est dans une liste connue.  
**Exemple de réponse**:
```json
{
  "message": "Le mot de passe est sécurisé."
}
```

#### **Vérifier un email**
**URL**: `/verif-mail/<mail>`  
**Méthode**: `GET`  
**Description**: Vérifie si une adresse email est valide.  

#### **Rechercher des informations DNS**
**URL**: `/search-dns/<dns>`  
**Méthode**: `GET`  
**Description**: Retourne les informations liées à un DNS donné.  

#### **Effectuer une recherche Google**
**URL**: `/crawling/<nom_prenom>`  
**Méthode**: `GET`  
**Description**: Effectue une recherche Google et retourne les résultats associés.  

---

### Actions non recommandées

#### **Spammer un email**
**URL**: `/spam-mail/<mail>`  
**Méthode**: `GET`  
**Description**: Envoie une série d'emails à une adresse donnée.  

#### **Spammer un site**
**URL**: `/ddos/<url>`  
**Méthode**: `GET`  
**Description**: Effectue un grand nombre de requêtes vers une URL donnée.  
