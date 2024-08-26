from django.shortcuts import render, redirect
from django.views.decorators.cache import never_cache


@never_cache
def dashboard_view(request):
    if request.user.is_authenticated:
        return render(request, 'dashboard.html')
    else:
        return redirect('login')

