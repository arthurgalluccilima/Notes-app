from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user


auth = Blueprint('auth', __name__)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully', category='sucess')
                login_user(user, remember=True) # this remeambers that a users is loggedin, unless the web servers restarts or thw user clena his cache
                return redirect(url_for('views.home'))
            else:
                flash('You typed the incorrect password, refreash your mind and try again', category='error')
        else:
            flash('Looks like your mail does not exist in database', category='error')

    return render_template("login.html", user=current_user)

@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method =='POST':
        email = request.form.get('email')
        firstName = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('You email is already linked to an account')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters', category='error')
        elif len(firstName) < 2:
            flash('First name must be grater than 1 character', category='error')
        elif password1 != password2:
            flash('The passwords don\'t match', category='error')
        elif len(password1) < 7:
            flash('Your assword must be a combination of at least 8 characters, number or simbols', category='error')
        else:
            new_user = User(email=email, first_name=firstName, password=generate_password_hash(password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            flash('Account created', category='sucess')
            return redirect(url_for('views.home'))

    return render_template("sign-up.html", user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))