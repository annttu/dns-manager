from django.forms import ModelForm, Form, CheckboxInput, BooleanField
from manager.models import Domain, Client, DNSEntryCache
from dnsutils import validate_data

class DomainForm(ModelForm):
    class Meta:
         model = Domain
         fields = ['name', 'comment', 'tsig_key', 'tsig_type', 'master']


class DomainEditForm(ModelForm):
    readonly_fields = ('name',)

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

    def clean_name(self):
        name = self.cleaned_data['name']
        return name.strip()

    def clean_data(self):
        data = self.cleaned_data['data']
        return data.strip()


class StaticEntryEditForm(StaticEntryForm):
    readonly_fields = ('name',)


class ConfirmDeleteForm(Form):
    confirmed = BooleanField(required=True)