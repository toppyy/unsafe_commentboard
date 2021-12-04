
from django.shortcuts               import redirect, render

from .models import Comment
from .models import User
from .models import AccessToken

from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponseRedirect

from .auth import hash_pw
from .auth import authenticate_request_username_pw
from .auth import create_token

from .decorators import login_required

from .misc import get_date

@csrf_exempt
@login_required
def index(request,token):

    if request.method == 'POST':
        comment_text    = request.POST.get('comment_text')
        pub_date        = get_date()
        new_comment     = Comment.objects.create(comment_text=comment_text,pub_date=pub_date,by=token.user.username)
        new_comment.save()

    
    comments = Comment.objects.all()
    
    return render(request, 'pages/index.html', { 'comments': comments  })



def register(request):
    if request.method == 'POST':

        new_user = User.objects.create(
            username    = request.POST.get('username'),
            password    = hash_pw(request.POST.get('password'))
        )
        new_user.save()


        token = AccessToken.objects.create(token=create_token(new_user.username,new_user.password),user=new_user)
        token.save()

        return redirect('/login')

    return render(request, 'pages/register.html')




def login(request):
    if request.method == 'POST':

            token = authenticate_request_username_pw(request)

            if token is not None:
                print('login ',token)

                response = HttpResponseRedirect('/')
                response.set_cookie('token',token.token)

                return response

            else:                
                message = { 'message': 'invalid password/username' }
                return render(request, 'pages/login.html',message)


    return render(request, 'pages/login.html', { 'message': '' })
