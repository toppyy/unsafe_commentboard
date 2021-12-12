from .models import User
from .models import AccessToken

import hashlib

SECRET = 'averybigsecret'


def md5(string):
    return hashlib.md5(string.encode('UTF-8')).hexdigest()

def hash_pw(password):
    return md5(password)


def create_token(username,password):
    return md5(username+'_'+password)


def authenticate_request_username_pw(request):

    if request.method == 'POST':
        username    = request.POST.get('username')
        password    = request.POST.get('password')
    else:
        return None

    if password is None or username is None:
        return None

    try:
        user = User.objects.get(username = username, password = hash_pw(password))
    except User.DoesNotExist:
        return None

    token = AccessToken.objects.get(user = user)

    return token


def authenticate_request_by_cookie(request):

    if 'token' not in request.COOKIES:
        return None

    token = request.COOKIES['token']

    try:
        accs_token = AccessToken.objects.filter(token = token).get()
    except AccessToken.DoesNotExist:
        return None
    
    return accs_token
