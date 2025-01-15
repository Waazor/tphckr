 # Mon Application Flask

## Prérequis

- Python 3.12
- MySQL

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
```

Importer les tables via le sql suivant : 

```bash

```
