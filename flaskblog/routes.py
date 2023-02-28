from flask import render_template, url_for, flash, redirect, request
from flask_login import login_user, logout_user, current_user, login_required

from flaskblog.forms import RegisterForm, LoginForm, UpdateAccountForm
from flaskblog.models import User, Post
from flaskblog import app, db, bcrypt
import secrets
import os
from PIL import Image

post = [
    {
        'author': 'Andy Anderson',
        'title': 'Blog Post 1',
        'content': 'First post content',
        'date_posted': 'June 25th, 2022'
    },
    {
        'author': 'John Smith',
        'title': 'Blog Post 2',
        'content': 'Second post content',
        'date_posted': 'June 26th, 2022'
    }
]


@app.route("/")
def home():
    return render_template('home.html', posts=post, title='Home')


@app.route("/about")
def about():
    return render_template('about.html', title='About')


@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()  # commit the changes to the database
        flash(f'Account created successfully for {form.username.data}, you are now able to log in', 'success')
        return redirect(url_for('home'))

    return render_template('register.html', title='Register', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            flash(f'Successfully logged in', 'success')
            return redirect(next_page) if next_page else redirect(url_for('home'))

        flash(f'Login Unsucessful. Please check email and password', 'danger')

    return render_template('login.html', title='Login', form=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))


def save_image(form_image):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_image.filename)
    image_fn = random_hex + f_ext
    image_path = os.path.join(app.root_path, 'static/profile_pics', image_fn)
    output_size = (125, 125)
    i = Image.open(form_image)
    i.thumbnail(output_size)
    i.save(image_path)

    return image_fn

@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    image_file = url_for('static', filename=f'profile_pics/{current_user.image_file}')
    if form.validate_on_submit():
        if form.image.data:
            image_path = save_image(form.image.data)
            current_user.image_file = image_path
        current_user.email = form.email.data
        current_user.username = form.username.data
        db.session.commit()  # commit the changes to the database
        flash(f'Successfully updated information', 'success')
        return redirect(url_for('account'))
    return render_template('account.html', title='Account', image_file=image_file, form=form)
