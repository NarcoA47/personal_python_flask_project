from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash 
from . import db
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint('auth', __name__)

@auth.route("/login", methods=['GET', 'POST'])
def login(): 
    if request.method == ('POST'):
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in Successfully', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password, try again', category='error')
        else:
            flash("Email does not exist", category='error')
    return render_template("login.html", user=current_user)

@auth.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        firstname = request.form.get('firstname')
        lastname= request.form.get('lastname')
        password_origin = request.form.get('password_origin')
        confirm_password = request.form.get('confirm_password')
        
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists', category='error')
        elif len(email) < 4:
            flash('Email must be more than 4 characters', category='error')
        elif len(firstname) < 2:
            flash('First name must be more than 3 characters', category='error')
        elif len(lastname) < 2:
            flash('Last name must be more than 3 characters', category='error')
        elif password_origin != confirm_password:
            flash('passwords must be equal', category='error')
        elif len(password_origin) < 8:
            flash('passwords must be more than 8 characters', category='error')
        else:
            new_user = User(email=email, firstname=firstname, lastname=lastname, password=generate_password_hash(password_origin, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            flash('Created successfully', category='success')
            return redirect(url_for('views.home'))
        
        
    return render_template("register.html", user=current_user)