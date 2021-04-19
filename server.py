from flask import Flask, render_template, request, redirect, session, flash
from mysqlconnection import connectToMySQL

import re	#the regex module
#this validates our email, MATCHES PATTERN
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
#this validates the names
NAME_REGEX = re.compile(r'^[[a-zA-Z]+$')

app = Flask(__name__)
app.secret_key = "speak friend and enter"
#need secret key for session

#imports b-crypt
from flask_bcrypt import Bcrypt        
bcrypt = Bcrypt(app)
# this needs to be after you declare app or it doesn't recognize

#RUN THIS TO LAUNCH python -m pipenv install flask PyMySQL
#AFTER YOU ACTIVATE RUN THIS to install bcrpt python -m pipenv install flask-bcrypt

#LANDING PAGES
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/success")
def success():
    return render_template("success.html")

#PROCESSES
@app.route('/register_user', methods=["POST"])
def register_user():
#VALIDATION
    is_valid = True
#REGEX VALIDATION
#checks validation from regex imported
    if not EMAIL_REGEX.match(request.form['email']):
        # test whether a field matches the pattern
        flash("Invalid email address!")
        is_valid = False
    if not NAME_REGEX.match(request.form['first_name']):
        # test whether a field matches the pattern
        flash("Invalid first name!")
        is_valid = False
    if not NAME_REGEX.match(request.form['last_name']):
        # test whether a field matches the pattern
        flash("Invalid last name!")
        is_valid = False
#FLASH VALIDATION
#basic if checks from flash
#make sure you add the FLASH MESSAGE LOOPS to your HTML!!! you keep forgetting!!
    if len(request.form['first_name']) < 1:
        is_valid = False
        flash("Please enter a first name")
    if len(request.form['last_name']) < 1:
        is_valid = False
        flash("Please enter a last name")
    if len(request.form['password']) < 8:
        is_valid = False
        flash("Password must be at least 8 characters")
    if request.form['password'] != request.form['password_confirm']:
        is_valid = False
        flash("Your passwords did not match")
#QUERY DB VALIDATORS
#see if the username/email provided exists in the database already
#query the db then check
    mysql = connectToMySQL("login_reg_schema")
    query = "SELECT * FROM users;"
    data = { }
    user_table = mysql.query_db(query, data)
#use a for loop to loop through the table
    for row in user_table:
        for i in row:
            if row['email'] == request.form['email']:
                is_valid = False
                flash("Email already taken")
                break
#VALIDATION COMPLETE            
#IF VALID, CONNECT TO DB
    if is_valid:
        #FIRST CALL THE DB
        mysql = connectToMySQL('login_reg_schema')
        #HASH THE PASSWORD
        pw_hash = bcrypt.generate_password_hash(request.form['password'])  
        print(pw_hash)
        #THEN QUERY THE DB
        query = "INSERT INTO users (first_name, last_name, email, password, created_at, updated_at) VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password)s, NOW(), NOW());"
        data = {
            "first_name": request.form["first_name"],
            "last_name": request.form["last_name"],
            "email": request.form["email"],
            "password": pw_hash #STORES HASHED PASSWORD
        }

        users = connectToMySQL("login_reg_schema").query_db(query,data)
        flash("Registration successful")

    return redirect("/")

@app.route('/login_user', methods=["POST"])
def login_user():
#VALIDATION

    #see if the username provided exists in the database
    #query the db
    mysql = connectToMySQL("login_reg_schema")
    query = "SELECT * FROM users WHERE email = %(email)s;"
    data = { "email" : request.form["email_login"] }

    #use the result variable to check the password, first make it a var
    result = mysql.query_db(query, data)

    #create var for the login password
    pw_hash_login = request.form['password_login']
    #check encrypted password
    if len(result) > 0:
        print(result[0]['password'])
        print(pw_hash_login)
        if bcrypt.check_password_hash(result[0]['password'], pw_hash_login):
            #put userid in session
            session['user_id'] = result[0]['id']
            return redirect('/success')

    flash("Invalid email or password, please try again")
    return redirect("/")

@app.route('/log_out', methods=["POST"])
def log_out():
    session.clear()
    return redirect("/")
#VALIDATION

if __name__ == "__main__":
    app.run(debug=True)