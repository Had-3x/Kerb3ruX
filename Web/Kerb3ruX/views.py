from django.shortcuts import render, redirect
from django.contrib import auth, messages
from django.contrib.auth.decorators import login_required

def login(request):
    if request.method == "GET":
        return render(request, "login.html")
    else:
        user = auth.authenticate(request, username=request.POST['username'], password=request.POST['password'])
        if user is None:
            messages.add_message(request, messages.ERROR, 'Username or Password Incorrect!!')
            return render(request, 'login.html')
        else: 
            auth.login(request, user)
            return redirect('dashboard')
     
@login_required
def dashboard(request):
    ctx = {"navbar": "active"}
    return render(request, 'dashboard.html', ctx)

def logout(request):
    auth.logout(request)
    return redirect('login')
