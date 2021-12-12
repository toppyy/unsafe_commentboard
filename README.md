# Unsafe comment board


Created for educational purposes
( [University of Helsinki MOOC on cyber security](https://cybersecuritybase.mooc.fi) )

A web application that has (at least) the following security flaws:
- Injection
    - CWE-79: Improper Neutralization of Input During Web Page Generation
- Cryptographic Failure
    - CWE-759: Use of a One-Way Hash without a Salt
    - CWE-327: Use of a Broken or Risky Cryptographic Algorithm
- Identification and Authentication Failures
    - CWE-521: Weak Password Requirements
    - CWE-613: Insufficient Session Expiration
- Broken access control
    - CWE-1275 Sensitive Cookie with Improper SameSite Attribute
- Security misconfiguration
    - CWE-756: Missing Custom Error Page

The flaws and their mitigation are documented [here](/documents/essay.md).


The application is a comment board created using [Django](https://www.djangoproject.com/).

To run the app:

    python3 manage.py runserver


