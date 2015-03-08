from django.forms import ModelForm
from manager.models import Domain, Client

class DomainForm(ModelForm):
    class Meta:
         model = Domain
         fields = ['name', 'comment', 'tsig_key', 'tsig_type', 'master']


class ClientForm(ModelForm):
    class Meta:
        model = Client
        fields = ['name', 'comment']



class ClientEditForm(ModelForm):
    class Meta:
        model = Client
        fields = ['comment',]