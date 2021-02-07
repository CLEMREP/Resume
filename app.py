import sqlite3, re
import hashlib, binascii, os
from datetime import *
from flask import Flask, redirect, url_for, render_template, request, session, abort, flash, g, jsonify

app = Flask(__name__)
app.secret_key = "cR25062003*"

DATABASE = 'dbportfolio.db'

def hash_password(password):
    """Hash a password for storing."""
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), 
                                salt, 100000)
    pwdhash = binascii.hexlify(pwdhash)
    return (salt + pwdhash).decode('ascii')

def verify_password(stored_password, provided_password):
    """Verify a stored password against one provided by user"""
    salt = stored_password[:64]
    stored_password = stored_password[64:]
    pwdhash = hashlib.pbkdf2_hmac('sha512', 
                                  provided_password.encode('utf-8'), 
                                  salt.encode('ascii'), 
                                  100000)
    pwdhash = binascii.hexlify(pwdhash).decode('ascii')
    return pwdhash == stored_password

def validateConnect(name, password, cursor):
    result = ""

    if any(not e for e in (name, password)):
        result += "Veuillez remplir tous les chanmps.\n"

    if not result:
        cursor.execute(f"SELECT password FROM utilisateurs WHERE nom = ({repr(name) });")
        if verify_password(str(cursor.fetchone()).replace("',)", "").replace("('", ""), password) is not True:
            result += "Nom / Mot de passe incorrect.\n"

    if not result:
        cursor.execute(f"SELECT nom FROM utilisateurs WHERE nom = ({ repr(name) });")
        if cursor.fetchone() is None:
            result += "Nom / Mot de passe incorrect.\n"

    return result

def validateForm(firstname, name, email, password, confirm_password, cursor):
    result = ""
    regex_email = "^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$"
    regex_password = "^.*(?=.{8,})(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=]).*$"

    if any(not e for e in (firstname, name, email, password, confirm_password)):
        result += "Veuillez remplir tous les champs.\n"
        
    else:
        if not 3 < len(firstname) < 16:
            result += "Le prénom doit faire entre 3 et 16 caractères.\n"

        if not 3 < len(name) < 16:
            result += "Le nom doit faire entre 3 et 16 caractères.\n"

        if not re.match(regex_email, email):
            result += "L'adresse mail n'est pas valide."

        if not 8 < len(password) < 64:
            result += "Le mot de passe doit faire entre 6 et 16 caractères.\n"

        if password != confirm_password:
            result += "Les mots de passe ne sont pas identiques.\n"

        if not re.match(regex_password,password):
            result += "Merci de renforcer votre mot de passe. Il doit contenir une majuscule, une minuscule, un numéro et un caractère spécial.\n"

        if not result:
            cursor.execute(f"SELECT nom FROM utilisateurs WHERE nom = ({ repr(name) });")
            if cursor.fetchone() is not None:
                result += "Le nom est déjà utilisé.\n"

            cursor.execute(f"SELECT email FROM utilisateurs WHERE email = ({ repr(email) });")
            if cursor.fetchone() is not None:
                result += "L'adresse mail est déjà utilisée.\n"
            
    return result

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/login", methods=["POST", "GET"])
def login():
    try:
        connexion = sqlite3.connect(DATABASE)
        cursor = connexion.cursor()

    except:
        flash("Une erreur est survenue, ressayer plus tard.")

    else:
        if request.method == "POST":
            name = request.form["name"]
            password = request.form["password"]
            #hour = str(datetime.now())

            isInvalidConnect = validateConnect(name, password, cursor)

            if isInvalidConnect:
                for error in isInvalidConnect.split("\n")[:-1]:
                    flash(error)

            else:
                try:
                    #cursor.execute(f"INSERT INTO log (nom, date) VALUES ({ repr(name) }, { repr(hour) });")
                    connexion.commit()

                except:
                    flash("Problème de connexion, ressayer plus tard.")

                else:
                    connexion.close()
                    return redirect("/admin/")


    return render_template("login.html")

@app.route("/register", methods=["POST", "GET"])
def register():
    try:
        connexion = sqlite3.connect(DATABASE)
        cursor = connexion.cursor()

    except:
        flash("Une erreur est survenue, ressayer plus tard.")

    else:
        if request.method == "POST":
            firstname = request.form["firstname"]
            name = request.form["name"]
            email = request.form["email"]
            password = request.form["password"]
            confirm_password = request.form["retypepassword"]
            inscription = str(date.today())

            isInvalidForm = validateForm(firstname, name, email, password, confirm_password, cursor)

            password = hash_password(password)

            if isInvalidForm:
                for error in isInvalidForm.split("\n")[:-1]:
                    flash(error)

            else:
                try:
                    cursor.execute(f"INSERT INTO utilisateurs (prenom, nom, email, password, date) VALUES ({ repr(firstname) }, { repr(name) }, { repr(email) }, { repr(password) }, { repr(inscription) });")
                    connexion.commit()

                except:
                    flash("Problème de connexion, ressayer plus tard.")

                else:
                    connexion.close()
                    flash("Création du compte avec succès.")
                    return redirect(url_for('login'))

    return render_template("register.html")

@app.route("/admin/")
def admin():
    try:
        connexion = sqlite3.connect(DATABASE)
        cursor = connexion.cursor()
        cursor.execute('SELECT id, prenom, nom, password, email, date FROM utilisateurs')
        items = cursor.fetchall()
        connexion.commit()

    except:
        flash("Problème de connexion, ressayer plus tard.")

    else:
        connexion.close()
        
    return render_template("/admin/index.html", items=items)


@app.route("/admin/edit/<name>", methods=["POST", "GET"])
def edit_user(name):
    try:
        connexion = sqlite3.connect(DATABASE)
        cursor = connexion.cursor()
        cursor.execute(f"SELECT id, prenom, nom, password, email, date FROM utilisateurs WHERE nom = { repr(name) };")
        infos = cursor.fetchall()

    except:
        flash("Problème de connexion, ressayer plus tard.")

    else:
        if request.method == "POST":
            new_firstname = request.form["new_firstname"]
            new_name = request.form["new_name"]
            new_email = request.form["new_email"]
            new_password = request.form["new_password"]

            new_password = hash_password(new_password)
            try:
                cursor.execute(f"UPDATE utilisateurs SET prenom = { repr(new_firstname) }, nom = { repr(new_name) }, email = { repr(new_email) }, password = { repr(new_password) } WHERE nom = { repr(name) };")
                connexion.commit()

            except:
                flash("Problème de la modification des informations.")

            else:
                connexion.close()
                flash(f"Le compte de { repr(name) } a bien été modifié.")
                return redirect(url_for('admin'))
        
    return render_template("/admin/edit.html", infos=infos)

@app.route("/logout")
def logout():
    return redirect(url_for('index'))

if __name__ == "__main__":
    app.run(debug=True)
