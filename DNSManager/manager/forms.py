from django.forms import ModelForm, Form, CheckboxInput
from manager.models import Domain, Client, DNSEntryCache
from dnsutils import validate_data

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


class StaticEntryForm(ModelForm):
    class Meta:
        model = DNSEntryCache
        fields = ['name', 'ttl', 'type', 'data']


class StaticEntryEditForm(StaticEntryForm):
    readonly_fields = ('name',)

class ConfirmDeleteForm(Form):
    confirmed = CheckboxInput(check_test=lambda x:True)