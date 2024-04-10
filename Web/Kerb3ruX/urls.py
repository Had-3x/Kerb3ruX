from django.urls import path

from . import views

urlpatterns = [
    path("", views.login, name="login"),
    path("login/", views.login),
    path("dashboard/", views.dashboard, name="dashboard"),
    path("logout/", views.logout, name="logout")
]