"""
Routes and views for the flask application.
"""

import os
from flask import Flask,render_template, redirect, url_for, jsonify, flash, request
import json
#from flaskdemo import app
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from sqlalchemy import ForeignKey
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from itsdangerous import URLSafeTimedSerializer
from flask_sendmail import Mail, Message
from flask_marshmallow import Marshmallow

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////flaskdemo/database.db'
app.config['MAIL_DEFAULT_SENDER'] = 'jigneshnagar007@yahoo.com'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
mail = Mail(app)
ma = Marshmallow(app)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    firstname = db.Column(db.String(20))
    lastname = db.Column(db.String(20))
    phonenumber = db.Column(db.String(10))


class UserSchema(ma.Schema):
    class Meta:
        # Fields to expose
        fields = ('id', 'username', 'email', 'password', 'firstname', 'lastname',
                  'phonenumber')


user_schema = UserSchema()
users_schema = UserSchema(many=True)


class Book(db.Model):
    book_id = db.Column(db.Integer, primary_key=True)
    book_name = db.Column(db.String(80))
    author = db.Column(db.String(50))
    publisher = db.Column(db.String(80))
    language = db.Column(db.String(20))
    genre = db.Column(db.String(20))
    price = db.Column(db.String(10))


class BookSchema(ma.Schema):
    class Meta:
        # Fields to expose
        fields = ('book_id', 'book_name', 'author', 'publisher', 'language',
                  'genre', 'price')


book_schema = BookSchema()
books_schema = BookSchema(many=True)


class Books(db.Model):
    books_id = db.Column(db.Integer, primary_key=True)
    book_name = db.Column(db.String(80))
    author_id = db.Column(db.Integer, ForeignKey('author_id'))
    #author_id = db.Column(db.Integer)
    publisher = db.Column(db.String(80))
    language = db.Column(db.String(20))
    genre = db.Column(db.String(20))
    price = db.Column(db.String(10))


class BooksSchema(ma.Schema):
    class Meta:
        # Fields to expose
        fields = ('books_id', 'book_name', 'author_id', 'publisher', 'language',
                  'genre', 'price')


books_schema = BooksSchema()
bookss_schema = BooksSchema(many=True)


class Author(db.Model):
    author_id = db.Column(db.Integer, primary_key=True)
    author_name = db.Column(db.String(80))


class AuthorSchema(ma.Schema):
    class Meta:
        # Fields to expose
        fields = ('author_id', 'author_name')


author_schema = AuthorSchema()
authors_schema = AuthorSchema(many=True)


class LoginForm(FlaskForm):
    username = StringField('username', validators = [InputRequired(),
                                              Length(min=4, max=15)])
    password = PasswordField('password', validators = [InputRequired(),
                                              Length(min=8, max = 80)])


class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(),
             Email(message='Invalid email'), Length(max=50)])
    username = StringField('User Name', validators=[InputRequired(),
                                             Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(),
                                              Length(min=8, max=80)])
    firstname = StringField('First Name', validators=[InputRequired()])
    lastname = StringField('Last Name', validators=[InputRequired()])
    phonenumber = StringField('Phone Number', validators=[InputRequired(),
                                                   Length(min=10,max=11)])


class EmailForm(FlaskForm):
    reset_email = StringField('Email', validators=[InputRequired(),
                    Email(message='Invalid email'), Length(max=50)])


class ResetForm(FlaskForm):
    reset_password = PasswordField('New Password', validators=[InputRequired(),
                                                        Length(min=8, max=80)])
    conf_password = PasswordField('Confirm Password', validators=[InputRequired(),
                                                          Length(min=8, max=80)])


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        try:
            user = User.query.filter_by(username=form.username.data).first()
            if user:
                if (user.password == form.password.data):
                    login_user(user)
                    flash('Login successfully','success')
                    return redirect(url_for('dashboard'))
                    #login_jsondata =  jsonify(data=form.data)
                else :
                    flash('Username or Password is incorrect','danger')
            else:
                flash('Username or Password is incorrect','danger')
        except Exception as e:
            flash(str(e),'danger')
    return render_template('login.html',form = form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
    #hashed_password = generate_password_hash(form.password.data, method='sha256')
        try:
            user = User.query.filter_by(username=form.username.data).first()
            email = User.query.filter_by(email=form.email.data).first()
            if user:
                flash('Username already created','danger')
            elif email:
                flash('Email already created', 'danger')
            else:
                new_user = User(username=form.username.data,
                     email=form.email.data, password=form.password.data,
                     firstname=form.firstname.data,lastname=form.lastname.data,
                     phonenumber=form.phonenumber.data)
                db.session.add(new_user)
                db.session.commit()
                flash('Registration Successful', 'success')
                return redirect(url_for('login'))
        except Exception as e:
            flash(str(e), 'danger')
            #signup_jsondata = jsonify(data=form.data)
    return render_template('signup.html', form = form)


@app.route('/email', methods=['GET','POST'])
def email_send():
    form = EmailForm()
    if form.validate_on_submit():
        try:
          reset_email = User.query.filter_by(email=form.reset_email.data).first()
          if reset_email :
              reset_link = send_password_reset_email(reset_email.email)
              flash('Please check your email for a password reset link.','success')
              flash(reset_link,'success')
              #return '<a href='+reset_link+'>Click here to reset password</a>'
              return redirect(url_for('login'))
          else :
              flash('Email address is incorrect', 'danger')
        except Exception as e:
            flash(str(e), 'danger')
    return render_template('email.html', form=form)


def send_password_reset_email(user_email):
    password_reset_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    password_reset_url = url_for('reset_with_token',
            token = password_reset_serializer.dumps(user_email, 
            salt='password-reset-salt'),_external=True)
    return password_reset_url
    #html = render_template('reset_password.html',form = ResetForm(),
                            #password_reset_url=password_reset_url)
    #msg = Message('Password Reset Requested',
           #sender=app.config['MAIL_DEFAULT_SENDER'],
                            # recipients=[user_email])
    #msg.html = render_template('reset_password.html',form = ResetForm())
    #mail.send(msg)


@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    try:
        password_reset_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        email = password_reset_serializer.loads(token, 
                      salt='password-reset-salt', max_age=3600)
    except:
        flash('The password reset link is invalid or has expired.','danger')
        return redirect(url_for('login'))
    form = ResetForm()
    if form.validate_on_submit():
        try:
            user = User.query.filter_by(email=email).first()
            reset_password = form.reset_password.data
            conf_password = form.conf_password.data
            if (reset_password != conf_password):
                flash('Password not matched','danger')
            else:
                db.session.add(user)
                db.session.commit()
                flash('Your password has been updated!','success')
                return redirect(url_for('login'))
        except Exception as e:
            flash('Invalid email address!','danger')
            return redirect(url_for('login'))
    return render_template('reset_password.html',form=form,token=token)


@app.route('/dashboard')
@login_required
def dashboard():
    data = db.session.query(Book)
    return render_template('dashboard.html',name=current_user.username,books=data)


@app.route('/insert', methods=['GET', 'POST'])
def insert():
    try:
        if request.method == "POST":
            book_name = request.form['bookname']
            author = request.form['author']
            publisher = request.form['publisher']
            language = request.form['language']
            genre = request.form['genre']
            price = request.form['price']
            new_book = Book(book_name=book_name, author=author,
                       publisher=publisher,language=language,
                       genre=genre, price=price)
            db.session.add(new_book)
            db.session.commit()
            flash('Data Inserted Successfully','success')
    except Exception as e:
        flash(str(e),'danger')
    return redirect(url_for('dashboard'))


@app.route('/update', methods=['GET', 'POST'])
def update():
    try:
        if request.method == "POST":
            id = request.form['id']
            book = Book.query.filter_by(book_id=id).first()
            book.book_name = request.form['bookname']
            book.author = request.form['author']
            book.publisher = request.form['publisher']
            book.language = request.form['language']
            book.genre = request.form['genre']
            book.price = request.form['price']
            db.session.commit()
            flash('Data Updated Successfully','success')
    except Exception as e:
        flash(str(e),'danger')
    return redirect(url_for('dashboard'))


@app.route('/delete/<string:id_data>', methods = ['GET', 'POST'])
def delete(id_data):
    try:
        flash('Record Has Been Deleted Successfully','success')
        book = Book.query.filter_by(book_id=id_data).first()
        db.session.delete(book)
        db.session.commit()
    except Exception as e:
        flash(str(e),'danger')
    return redirect(url_for('dashboard'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.errorhandler(404)
def page_not_found(e):
    return jsonify(error=404, text=str(e)), 404


# endpoint to create new book
@app.route('/api/book', methods=['POST'])
def add_book():
    book_name = request.json['bookname']
    author = request.json['author']
    publisher = request.json['publisher']
    language = request.json['language']
    genre = request.json['genre']
    price = request.json['price']
    new_book = Book(book_name=book_name,author=author,publisher=publisher,language=language,genre=genre,price=price)
    db.session.add(new_book)
    db.session.commit()
    return book_schema.jsonify(new_book)


# endpoint to show all books
@app.route('/api/book', methods=['GET'])
def get_book():
    all_books = Book.query.all()
    result = books_schema.dump(all_books)
    return jsonify(result.data)


# endpoint to get book detail by id
@app.route('/api/book/<id>', methods=['GET'])
def book_detail(id):
    book = Book.query.get(id)
    return book_schema.jsonify(book)


# endpoint to update book
@app.route('/api/book/<id>', methods=['PUT'])
def book_update(id):
    book = Book.query.get(id)
    book_name = request.json['bookname']
    author = request.json['author']
    publisher = request.json['publisher']
    language = request.json['language']
    genre = request.json['genre']
    price = request.json['price']
    book.book_name = book_name
    book.author = author
    book.publisher = publisher
    book.language = language
    book.genre = genre
    book.price = price
    db.session.commit()
    return book_schema.jsonify(book)


# endpoint to delete book
@app.route('/api/book/<id>', methods=['DELETE'])
def book_delete(id):
    book = Book.query.get(id)
    db.session.delete(book)
    db.session.commit()
    return book_schema.jsonify(book)


# endpoint to create new user
@app.route("/api/user", methods=["POST"])
def add_user():
    username = request.json['username']
    email = request.json['email']
    password = request.json['password']
    firstname = request.json['firstname']
    lastname = request.json['lastname']
    phonenumber = request.json['phonenumber']
    new_user = User(username = username, email = email, password = password,
                    firstname = firstname, lastname = lastname,
                    phonenumber = phonenumber)
    db.session.add(new_user)
    db.session.commit()
    return user_schema.jsonify(new_user)


# endpoint to show all users
@app.route("/api/user", methods=["GET"])
def get_user():
    all_users = User.query.all()
    result = users_schema.dump(all_users)
    return jsonify(result.data)


# endpoint to get user detail by id
@app.route("/api/user/<id>", methods=["GET"])
def user_detail(id):
    user = User.query.get(id)
    return user_schema.jsonify(user)


# endpoint to update user
@app.route("/api/user/<id>", methods=["PUT"])
def user_update(id):
    user = User.query.get(id)
    username = request.json['username']
    email = request.json['email']
    password = request.json['password']
    firstname = request.json['firstname']
    lastname = request.json['lastname']
    phonenumber = request.json['phonenumber']
    user.username = username
    user.email = email
    user.password= password
    user.firstname = firstname
    user.lastname = lastname
    user.phonenumber = phonenumber
    db.session.commit()
    return user_schema.jsonify(user)


# endpoint to delete user
@app.route("/api/user/<id>", methods=["DELETE"])
def user_delete(id):
    user = User.query.get(id)
    db.session.delete(user)
    db.session.commit()
    return user_schema.jsonify(user)


# endpoint to get books detail by id
@app.route("/api/books/<id>", methods=["GET"])
def books_detail(id):
    books = Books.query.get(id)
    return books_schema.jsonify(books)


# endpoint to update book
@app.route('/api/books/<id>', methods=['PUT'])
def books_update(id):
    books = Books.query.get(id)
    book_name = request.json['bookname']
    author_id = request.json['author_id']
    publisher = request.json['publisher']
    language = request.json['language']
    genre = request.json['genre']
    price = request.json['price']
    books.book_name = book_name
    books.author_id = author_id
    books.publisher = publisher
    books.language = language
    books.genre = genre
    books.price = price
    db.session.commit()
    return books_schema.jsonify(books)


if __name__ == '__main__':
    
    HOST = os.environ.get('SERVER_HOST', 'localhost')
    try:
        PORT = int(os.environ.get('SERVER_PORT', '5555'))
    except ValueError:
        PORT = 5555
    app.run(HOST, PORT)
    #app.run(host='0.0.0.0',debug = True, port=5001)