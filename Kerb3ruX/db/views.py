from django.http import HttpResponse
from django.shortcuts import render
from Kerb3ruX.dataBaseManager import DataBaseManager


def index(request) -> HttpResponse:
    return render(request, 'index.html', {
            'command': request.GET.get("command", None),
            'response': request.GET.get('response', "ERROR: could not get a response"),
        })
