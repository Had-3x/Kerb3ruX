from django import forms


class Command(forms.Form):
    command: str = forms.CharField()
