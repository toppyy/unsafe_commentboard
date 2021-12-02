# Unsafe comment board


Created for educational purposes
( [University of Helsinki MOOC on cyber security](https://cybersecuritybase.mooc.fi) )

A web application that has the following security flaws:
- Injection
- Cryptographic Failure
    - DB uses unsalted hashes to store passwords with deprecated hash function

The application is a comment board created using [Django](https://www.djangoproject.com/).

To run the app:

    python3 manage.py runserver


