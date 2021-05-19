# adib-blog My Personal Blog Website.
A website I built while studying course 100 Days Of Code created by Dr. Angela Yu.
* https://adib-blog.herokuapp.com/
* Blog built with Flask


## Functionality
* Users need to register/login in order to comment on posts.
* Passwords are securely encoded with hashing and salting functions of the werkzeug.security package.
* Only Admin users can create and delete posts.
* (Production) WSGI server is setup with Gunicorn to run the Live Python Application on Heroku. PostgreSQL database is used for production.
* (Development) Development and testing is done locally with a SQLite database.
## Topics covered
* Python, HTML, CSS, Heroku, SQL
* Flask Web Framework
* SQL Databases
* Decorators
* OOP
* Functions
### Packages
* See requirements.txt for all packages and dependencies used.
