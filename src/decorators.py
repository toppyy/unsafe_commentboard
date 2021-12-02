
from django.shortcuts import redirect

from .auth import hash_pw
from .auth import authenticate_request_by_cookie
from .auth import authenticate_request_username_pw



def login_required(viewfunction):


    def authenticate(*args):

        request = args[0]
        authenticated           = authenticate_request_username_pw(request)
        authenticated_cookie    = authenticate_request_by_cookie(request)

        print('auth',authenticated,authenticated_cookie)

        if authenticated is not None or authenticated_cookie is not None:

          return viewfunction(*args)

        return redirect('/login') 

    return authenticate

