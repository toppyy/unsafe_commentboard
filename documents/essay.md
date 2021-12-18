# Security flaws and their mitigation

Link to repo: [https://github.com/toppyy/unsafe_commentboard](https://github.com/toppyy/unsafe_commentboard)

To install (assuming Django is installed):

    python3 manage.py makemigrations
    python3 manage.py migrate

Start app:

    python3 manage.py runserver



# Flaws

All flaws are from the OWASP Top Ten 2021 -list.

## Flaw 1: A03 Injection

The application is vulnerable to Cross-Site Scripting (XSS), more specifically  [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html).

The flaw is due to the following lines in a templatefile:
https://github.com/toppyy/unsafe_commentboard/blob/master/src/templates/pages/index.html#L19-L20

The application displays the username, date and content of comments made by users in an HTML-table. The username and comment content originate from the user and therefore can contain malicious content. Both are stored in the application database and are retrieved and displayed upon request of *index.html*.

By default Django escapes dynamic content rendered within the template. However, applying the tags "safe" and "escape", the app prints the username and the comment unescaped. This leads to execution of whatever code a user enters to the username/comment -field. For example, the following comment would print 'hello' to a client's browser console while displaying the comment content in the table. 

    `<script>alert('hello')</script>Comment content` 

The issue can mitigated by removing the string of tag ("safe|escape") from the template. Also, the server could impose restrictions on the comment content and the username when they are initially POSTed to the server.

## Flaw 2: A02 Cryptographic Failure

The application stores credentials of registered users. The username is stored as plaintext, the password is hashed after concatenated with a pepper. The hashing function used is MD5. 

However, MD5 is considered as an unsafe hashing function (see
[CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html) ). 

MD5 is used in this line of code:
https://github.com/toppyy/unsafe_commentboard/blob/master/src/auth.py#L10

To mitigate the issue, passwords should be hashed using a different hashing function like *Argon2id* or *bcrypt*.  

Also, the application does not salt the passwords (see issue [CWE-759: Use of a One-Way Hash without a Salt](https://cwe.mitre.org/data/definitions/759.html)). While peppering creates additional security, it is not a replacement for salting. To mitigate this, the application should create a salt for each stored password and store it along the password. 

Also, the secret key used for peppering is stored in the source code and not in a key vault.


## Flaw 3: A07 Identification and Authentication Failures
  
The app has two distinct flaws under this category:

- [CWE-521: Weak password requirements](https://cwe.mitre.org/data/definitions/521.html)
- [CWE-613: Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html)

The app has no restrictions regarding usernames and passwords (see lines https://github.com/toppyy/unsafe_commentboard/blob/master/src/views.py#L39-L42 ). A password/username can be of any length or content, for example "username" and "password" are valid as credentials. As there are no restrictions, this is also an injection point. 

Having no restrictions on passwords/usernames creates a situation where a user is can use a password that's very common or not sufficiently long. This makes it easier to crack passwords by brute forcing, rainbow table password cracking etc. 

To mitigate the issue, one could enforce restrictions on credentials like to following: minimum and maximum length, no reuse, no common passwords, password must include mixed character sets, passwords expire etc.

The app uses a access token stored as a cookie for session control (= check if user is already logged in): 
https://github.com/toppyy/unsafe_commentboard/blob/master/src/views.py#L65

The cookie or the token (stored in the db) have no expiration dates and so a valid token can be used to log in forever. 


