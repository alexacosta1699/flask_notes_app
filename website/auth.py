from crypt import methods
from flask import Blueprint, render_template, request, flash, redirect, url_for
#manages access to pages whether a user is logged in or not and current user info
from flask_login import login_required, logout_user, login_user, current_user
from website.models import User
from . import db
from werkzeug.security import generate_password_hash, check_password_hash


#setting up blueprint
auth = Blueprint('auth',__name__)

@auth.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        #get form data
        email = request.form.get('email')
        password = request.form.get('password')
        #query db
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in sucessfully!', category='success')
                login_user(user,remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect Password!', category='error')             
        else:
            flash('Email does not exist!', category='error')
    return render_template("login.html", user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/sign_up', methods=['GET','POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        firstName = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        #data validation
        user = User.query.filter_by(email=email).first()
        if user:
            flash("User already exists!", category='error')
        elif len(email) < 4:
            flash('Email must be greater than 4 characters',category='error')
        elif len(firstName) < 2:
            flash('First name must be greater than 3 characters',category='error')
        elif password1 != password2:
            flash('Passwords don\'t match',category='error')
        elif len(password1) < 7:
            flash('Password is too short. Password must be at least 8 characters.',category='error')
        else:
            new_user = User(email=email,firstName=firstName,password=generate_password_hash(password1,method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(user,remember=True)
            flash('Account created!',category='success')
            return redirect(url_for("views.home"))
    return render_template("sign_up.html",user=current_user)