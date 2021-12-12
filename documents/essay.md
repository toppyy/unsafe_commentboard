# Security flaws and their mitigation

Link to repo: [https://github.com/toppyy/unsafe_commentboard](https://github.com/toppyy/unsafe_commentboard)

To install (assuming Django is installed):

    python3 manage.py makemigrations
    python3 manage.py migrate

Start app:

    python3 manage.py runserver


# Flaws

## Flaw 1:

The application is vulnerable to Cross-Site Scripting (XSS), more specifically  [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html).

The flaw 

