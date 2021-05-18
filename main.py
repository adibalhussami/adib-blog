from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, Text, ForeignKey
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def admin_only(function):
    @wraps(function)
    def wrapper_function(*args, **kwargs):
        if current_user.id == 1:
            return function(*args, **kwargs)

        return abort(403, description="You don't have permission")

    return wrapper_function


# CONFIGURE TABLES

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(250), nullable=False, unique=True)
    password = Column(String(250), nullable=False)
    name = Column(String(250), nullable=False)
    posts = relationship('BlogPost', back_populates='author')
    comments = relationship('Comment', back_populates='comment_author')


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = Column(Integer, primary_key=True)
    author_id = Column(Integer, ForeignKey('users.id'))
    author = relationship('User', back_populates='posts')
    title = Column(String(250), unique=True, nullable=False)
    subtitle = Column(String(250), nullable=False)
    date = Column(String(250), nullable=False)
    body = Column(Text, nullable=False)
    img_url = Column(String(250), nullable=False)
    comments = relationship('Comment', back_populates='comments_post')


class Comment(db.Model):
    __tablename__ = "comments"
    id = Column(Integer, primary_key=True)

    author_id = Column(Integer, ForeignKey('users.id'))
    comment_author = relationship('User', back_populates='comments')

    post_id = Column(Integer, ForeignKey('blog_posts.id'))
    comments_post = relationship('BlogPost', back_populates='comments')

    text = Column(Text, nullable=False)


db.create_all()


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated)


@app.route('/register', methods=['POST', 'GET'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash("you've already signed up with this email. login instead")
            return redirect(url_for('login'))
        password = generate_password_hash(
            password=form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=form.email.data,
            password=password,
            name=form.name.data

        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/login', methods=['POST', 'GET'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if not user:
            flash('This email does not exist, please register first or try again')
            return redirect(url_for('login'))

        elif not check_password_hash(user.password, form.password.data):
            flash("Incorrect password, please try again.")
            return redirect(url_for('login'))

        else:
            login_user(user)
            return redirect(url_for('get_all_posts'))

    return render_template("login.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comment_form = CommentForm()
    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash('Please sign in first')
            return redirect(url_for('login'))
        else:
            new_comment = Comment(
                text=comment_form.comment.data,
                author_id=current_user.id,
                post_id=requested_post.id
            )
            db.session.add(new_comment)
            db.session.commit()
    return render_template(
        "post.html",
        post=requested_post,
        form=comment_form,
        logged_in=current_user.is_authenticated
    )


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


@app.route("/new-post", methods=['POST', 'GET'])
@login_required
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author_id=current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>", methods=['POST', 'GET'])
@login_required
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
