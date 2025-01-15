import os

from flask import Flask, jsonify, request
from flasgger import Swagger
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token,get_jwt
from bcrypt import hashpw, gensalt, checkpw
from functools import wraps
from dotenv import load_dotenv
import datetime

from personCreator import generate_image
from dnsFind import virus_total_search
from fakeIdentity import create_fake_identity
from mailSpammer import spam_email
from passwordCreator import create_password
from verifMail import verify_email
from verifPassword import check_if_pwd_is_on_list
from crawler import google_search, extract_info
from ddos import spam_request

load_dotenv()

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv('BDD')
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = os.getenv('SECRET_KEY')
app.config["SWAGGER"] = {
    "title": "API sécurisée avec JWT",
    "uiversion": 3,
    "securityDefinitions": {
        "Bearer": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "Entrez votre token JWT sous la forme : Bearer <votre_token>"
        }
    },
    "security": [{"Bearer": []}],
}

swagger = Swagger(app)
jwt = JWTManager(app)
db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)

class Log(db.Model):
    __tablename__ = "logs"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    endpoint = db.Column(db.String(255), nullable=False)
    method = db.Column(db.String(10), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.datetime.today)
    status_code = db.Column(db.Integer, nullable=False)

@app.after_request
def log_request(response):
    try:
        endpoint = request.endpoint
        method = request.method
        status_code = response.status_code

        user_id = None
        if "Authorization" in request.headers:
            try:
                claims = get_jwt()
                user_id = claims.get("sub")
            except Exception:
                pass

        log = Log(
            user_id=user_id,
            endpoint=endpoint,
            method=method,
            status_code=status_code,
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        app.logger.error(f"Erreur lors de la création du log : {str(e)}")

    return response


def role_required(allowed_roles):
    def decorator(func):
        @wraps(func)
        @jwt_required()
        def wrapper(*args, **kwargs):
            claims = get_jwt()
            user_role = claims.get("role")
            if user_role not in allowed_roles:
                return jsonify({"message": "Accès non autorisé pour votre rôle"}), 403
            return func(*args, **kwargs)
        return wrapper
    return decorator

@app.route("/create-user", methods=["POST"])
@role_required("admin")
def create_user():
    """
    Créer un nouvel utilisateur
    ---
    tags:
        - Admin tools
    parameters:
        - name: body
          in: body
          required: true
          description: Informations de l'utilisateur
          schema:
            type: object
            properties:
                username:
                    type: string
                password:
                    type: string
                role:
                    type: string
    security:
        - Bearer: []
    responses:
        201:
            description: Utilisateur créé avec succès
        400:
            description: Erreur dans les données fournies
        401:
            description: Accès non autorisé
    """
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    role = data.get("role")


    if role not in ["admin", "good_guy", "bad_guy"]:
        return jsonify({"error": "Le rôle doit être 'admin', 'good_guy' ou 'bad_guy'"}), 400

    if not username or not password:
        return jsonify({"error": "Le username et le mot de passe sont obligatoires"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Cet utilisateur existe déjà"}), 400

    hashed_password = hashpw(password.encode("utf-8"), gensalt()).decode("utf-8")

    new_user = User(username=username, password=hashed_password, role=role,created_at=datetime.datetime.today())
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "Utilisateur créé avec succès"}), 201


@app.route("/login", methods=["POST"])
def login():
    """
    Authentification utilisateur
    ---
    tags:
        - JWT
    parameters:
        - name: body
          in: body
          required: true
          description: Identifiants de l'utilisateur
          schema:
            type: object
            properties:
                username:
                    type: string
                password:
                    type: string
    responses:
        200:
            description: Token JWT généré
    """

    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    user = User.query.filter_by(username=username).first()

    if user and checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        token = create_access_token(identity=str(user.id),additional_claims={"role": user.role})
        return jsonify(access_token=token), 200
    else:
        return jsonify({"message": "Identifiants invalides"}), 401

@app.route("/create-password/<int:taille>", methods=["GET"])
@jwt_required()
def create_password_endpoint(taille):
    """
    Génère un mot de passe aléatoire sécurisé
    ---
    tags:
        - Create someone
    security:
        - Bearer: []
    parameters:
        - name: taille
          in: path
          type: integer
          required: true
          description: La longueur souhaitée pour le mot de passe (minimum 6 caractères)
    responses:
        200:
            description: Mot de passe généré avec succès
        400:
            description: La longueur spécifiée est invalide (sa taille doit être supérieur à 6)
        401:
            description: Accès non autorisé. Token JWT manquant ou invalide
    """

    length = taille

    if length < 6:
        return jsonify({"error": "La longueur doit être d'au moins 6 caractères"}), 400

    password = create_password(length)
    return jsonify({"password": password}), 200



@app.route("/create-fake-identity")
@jwt_required()
def create_identity():
    """
    Génère une fausse identité
    ---
    tags:
        - Create someone
    security:
        - Bearer: []
    responses:
        200:
            description: Retourne une fausse identité
        401:
            description: Accès non autorisé
    """

    fake_name, fake_mail, fake_address, fake_phone = create_fake_identity()
    return jsonify({
        'name': fake_name,
        'email': fake_mail,
        'address': fake_address,
        'phone': fake_phone
    })

@app.route("/verif-password/<string:password>")
@jwt_required()
def verify_password(password):
    """
    Vérifie si le mot de passe est dans une liste de mots de passe
    ---
    parameters:
        - name: password
          in: path
          type: string
          required: true
          description: Le mot de passe à vérifier
    tags:
        - Search on web
    security:
        - Bearer: []
    responses:
        200:
            description: Résultat de la vérification
        401:
            description: Accès non autorisé
    """

    return check_if_pwd_is_on_list(password)

@app.route("/search-dns/<string:dns>")
@jwt_required()
def search_dns(dns):
    """
    Cherche tous les DNS liés à celui entré
    ---
    parameters:
        - name: dns
          in: path
          type: string
          required: true
          description: Entrez le DNS que vous voulez analyser
    tags:
        - Search on web
    security:
        - Bearer: []
    responses:
        200:
            description: Voici les DNS liés trouvés

        401:
            description: Accès non autorisé
    """

    return virus_total_search(dns)

@app.route("/verif-mail/<string:mail>")
@jwt_required()
def verif_mail(mail):
    """
    Vérifie si une adresse mail est valide
    ---
    parameters:
        - name: mail
          in: path
          type: string
          required: true
          description: L'adresse email à vérifier
    tags:
        - Search on web
    security:
        - Bearer: []
    responses:
        200:
            description: Résultat de la vérification de l'email
        401:
            description: Accès non autorisé
    """

    return verify_email(mail)

@app.route("/spam-mail/<string:mail>")
@role_required(["bad_guy", "admin"])
def spam_mail(mail,object_mail,content_mail):
    """
    Créer un spam de mail
    ---
    tags:
        - Not cools things
    parameters:
        - name: mail
          in: path
          type: string
          required: true
          description: Le mail que vous voulez spam
        - name: object_mail
          in: query
          type: string
          required: true
          description: L'objet du mail
        - name: content_mail
          in: query
          type: string
          required: true
          description: Le contenu du mail
    security:
        - Bearer: []
    responses:
        200:
            description: Le spam a été fait !
        401:
            description: Accès non autorisé
    """

    spam_email(mail, object_mail, content_mail)

@app.route("/create-person")
@jwt_required()
def create_person():
    """
    Génère une image aléatoire
    ---
    tags:
        - Create someone
    security:
        - Bearer: []
    responses:
        200:
            description: Retourne une image aléatoire
            content:
                image/jpeg:
                    schema:
                        type: string
                        format: binary
        401:
            description: Accès non autorisé
    """
    return generate_image()

@app.route("/crawling/<string:nom_prenom>")
@jwt_required()
def crawling(nom_prenom):
    """
    Recherche des informations sur le nom et prénom fournis via Google
    ---
    parameters:
        - name: nom_prenom
          in: path
          type: string
          required: true
          description: Le nom et le prénom de la personne que vous cherchez
    tags:
        - Search on web
    security:
        - Bearer: []
    responses:
        200:
            description: La recherche a été faite
        401:
            description: Accès non autorisé
    """
    print(f"Recherche d'informations sur : {nom_prenom}")
    html_content = google_search(nom_prenom)

    if html_content:
        results = extract_info(html_content)
        if results:
            return jsonify({"results": [{"title": title, "link": link} for title, link in results]})
        else:
            return jsonify({"message": "Aucun résultat pertinent trouvé."})
    else:
        return jsonify({"message": "Impossible de récupérer les informations."})

@app.route("/ddos/<string:url>")
@role_required(["bad_guy", "admin"])
def ddos(url):
    """
    Spammer un site de requêtes
    ---
    parameters:
        - name: url
          in: path
          type: string
          required: true
          description: Le site que vous voulez spammer avec des requêtes
    tags:
        - Not cools things
    security:
        - Bearer: []
    responses:
        200:
            description: Le spam a été effectué avec succès
        401:
            description: Accès non autorisé
    """

    spam_request(url)
    return jsonify({"message": "Le spam a été effectué avec succès."})

@app.route('/users/<int:user_id>', methods=['DELETE'])
@role_required("admin")
def delete_user(user_id):
    """
    Supprimer un utilisateur par ID
    ---
    tags:
        - Admin tools
    parameters:
        - name: user_id
          in: path
          type: integer
          required: true
          description: ID de l'utilisateur à supprimer
    security:
        - Bearer: []
    responses:
        200:
            description: L'utilisateur a été supprimé avec succès
        404:
            description: Utilisateur introuvable
        500:
            description: Erreur interne du serveur
    """

    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'message': 'Utilisateur introuvable'}), 404

        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': f"Utilisateur avec l'ID {user_id} supprimé avec succès"}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/users', methods=['GET'])
@role_required("admin")
def get_all_users():
    """
    Récupérer tous les utilisateurs
    ---
    tags:
        - Admin tools
    security:
        - Bearer: []
    responses:
        200:
            description: Liste de tous les utilisateurs
            content:
                application/json:
                    schema:
                        type: array
                        items:
                            type: object
                            properties:
                                id:
                                    type: integer
                                username:
                                    type: string
                                role:
                                    type: string
                                created_at:
                                    type: string
                                    format: date-time
                        example:
                            - id: 1
                              username: "admin"
                              role: "admin"
                              created_at: "2022-01-01T00:00:00Z"
        500:
            description: Erreur interne du serveur
    """

    try:
        users = User.query.all()
        user_list = []
        for user in users:
            user_list.append({
                'id': user.id,
                'username': user.username,
                'role': user.role,
                'created_at': user.created_at,
            })
        return jsonify(user_list), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/logs', methods=['GET'])
@role_required("admin")
def get_logs():
    """
    Récupérer tous les logs
    ---
    tags:
        - Admin tools
    security:
        - Bearer: []
    responses:
        200:
            description: Liste de tous les logs
            content:
                application/json:
                    schema:
                        type: array
                        items:
                            type: object
                            properties:
                                id:
                                    type: integer
                                user_id:
                                    type: integer
                                endpoint:
                                    type: string
                                method:
                                    type: string
                                status_code:
                                    type: integer
                                timestamp:
                                    type: string
                                    format: date-time
                        example:
                            - id: 1
                              user_id: 1
                              endpoint: "/users"
                              method: "GET"
                              status_code: 200
                              timestamp: "2022-01-01T00:00:00Z"
        500:
            description: Erreur interne du serveur
    """

    try:
        logs = Log.query.order_by(Log.timestamp.desc()).all()
        log_list = []
        for log in logs:
            log_list.append({
                'id': log.id,
                'user_id': log.user_id,
                'endpoint': log.endpoint,
                'method': log.method,
                'status_code': log.status_code,
                'timestamp': log.timestamp
            })
        return jsonify(log_list), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/logs/<int:user_id>', methods=['GET'])
def get_logs_by_user(user_id):
    """
    Récupérer les logs pour un utilisateur spécifique
    ---
    tags:
        - Admin tools
    security:
        - Bearer: []
    parameters:
        - name: user_id
          in: path
          type: integer
          required: true
          description: ID de l'utilisateur pour filtrer les logs
    responses:
        200:
            description: Liste des logs pour l'utilisateur spécifié
            content:
                application/json:
                    schema:
                        type: array
                        items:
                            type: object
                            properties:
                                id:
                                    type: integer
                                user_id:
                                    type: integer
                                endpoint:
                                    type: string
                                method:
                                    type: string
                                status_code:
                                    type: integer
                                timestamp:
                                    type: string
                                    format: date-time
                        example:
                            - id: 1
                              user_id: 1
                              endpoint: "/users"
                              method: "GET"
                              status_code: 200
                              timestamp: "2022-01-01T00:00:00Z"
        404:
            description: Aucun log trouvé pour cet utilisateur
        500:
            description: Erreur interne du serveur
    """

    try:
        logs = Log.query.filter_by(user_id=user_id).order_by(Log.timestamp.desc()).all()
        if not logs:
            return jsonify({'message': f"Aucun log trouvé pour l'utilisateur avec l'ID {user_id}"}), 404

        log_list = [
            {
                'id': log.id,
                'user_id': log.user_id,
                'endpoint': log.endpoint,
                'method': log.method,
                'status_code': log.status_code,
                'timestamp': log.timestamp
            } for log in logs
        ]
        return jsonify(log_list), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)

