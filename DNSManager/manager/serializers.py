# Serializers for django rest framework
from django.contrib.auth.models import User
from rest_framework import serializers

import dnsutils
from manager.models import Domain, DNSEntryCache


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('pk', 'username', 'email')


class DomainSerializer(serializers.Serializer):
    """
    name = models.CharField(max_length=128, null=False, unique=True)
    comment = models.CharField(max_length=8192, null=False, default="")
    users = models.ManyToManyField(User)  # Users can do things to Domain
    groups = models.ManyToManyField(Group)  # Users on groups can do things to Domain
    tsig_key = models.CharField(max_length=8192, null=False, validators=[tsig_key_validator])
    tsig_type = models.CharField(max_length=8192, null=False, default="HMAC_MD5", choices=TSIG_KEY_TYPES)
    master = models.CharField(max_length=8192, null=False, help_text="DNS zone master server address", validators=[check_master])
    """
    pk = serializers.IntegerField(read_only=True)
    name = serializers.CharField(required=True, allow_blank=False, max_length=128)
    comment = serializers.CharField(required=True, allow_blank=True, max_length=8192)
    users = UserSerializer(many=True, read_only=True)
    tsig_key = serializers.CharField(required=True, allow_blank=False, max_length=8192)
    tsig_type = serializers.CharField(required=True, allow_blank=False, max_length=8192)
    master = serializers.CharField(required=True, allow_null=False, allow_blank=False, max_length=256)

    def create(self, validated_data):
        return Domain.objects.create(**validated_data)

    def update(self, instance, validated_data):

        instance.name = validated_data.get('name', instance.name)
        instance.comment = validated_data.get('comment', instance.comment)
        instance.tsig_key = validated_data.get('tsig_key', instance.tsig_key)
        instance.tsig_type = validated_data.get('tsig_type', instance.tsig_type)
        instance.master = validated_data.get('master', instance.master)

        instance.save()
        return instance


class DNSEntryCacheSerializer(serializers.Serializer):
    """
    domain = models.ForeignKey(Domain)
    name = models.CharField(max_length=128, null=False, blank=True)
    ttl = models.IntegerField(null=False, default=360)
    record_class = models.CharField(max_length=128, null=False, default="IN", blank=False)
    type = models.CharField(max_length=128, null=False, blank=False)
    data = models.CharField(max_length=8192, null=False, blank=False)
    timestamp = models.DateTimeField(auto_now_add=True, auto_created=True, null=False)

    """

    # domain = DomainSerializer(read_only=True, allow_null=False)
    pk = serializers.IntegerField(read_only=True)
    name = serializers.CharField(required=False, allow_blank=True, allow_null=False, max_length=128)
    ttl = serializers.IntegerField(min_value=0, max_value=864000, default=360)
    record_class = serializers.ChoiceField(choices=[('IN', 'IN')], default='IN')
    type = serializers.CharField(required=False, max_length=10, allow_blank=False, allow_null=False)
    data = serializers.CharField(required=False, allow_blank=False, allow_null=False, max_length=255)
    timestamp = serializers.DateTimeField(read_only=True, required=False)

    def create(self, validated_data):
        print(validated_data)
        domain = validated_data['domain']

        instance = DNSEntryCache.objects.create(**validated_data)

        return instance

    def update(self, instance, validated_data):

        instance.data = validated_data.get('data', instance.data)
        instance.type = validated_data.get('type', instance.type)
        instance.name = validated_data.get('name', instance.name)
        instance.ttk = validated_data.get('ttl', instance.ttl)
        instance.record_class = validated_data.get('record_class', instance.record_class)

        instance.save()
        return instance
