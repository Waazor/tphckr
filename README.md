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

