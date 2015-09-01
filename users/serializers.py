from django.contrib.auth.models import User, Group
from rest_framework import serializers
from oauth2_provider.models import Application, AccessToken, RefreshToken

from django.utils import timezone


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        write_only_fields = ('password',)


class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group


class SignUpSerializer(serializers.ModelSerializer):
    client_id = serializers.SerializerMethodField()
    client_secret = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ('username', 'password', 'client_id', 'client_secret')
        # write_only_fields = ('password',)

    def get_client_id(self, obj):
        return Application.objects.get(user=obj).client_id

    def get_client_secret(self, obj):
        return Application.objects.get(user=obj).client_secret

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
            instance.save()
        return instance

    def update(self, instance, validated_data):
        for attr, value in validated_data.items():
            if attr == 'password':
                instance.set_password(value)
            else:
                setattr(instance, attr, value)
        instance.save()
        return instance


class LoginSerializer(SignUpSerializer):
    access_token = serializers.SerializerMethodField()
    refresh_token = serializers.SerializerMethodField()
    expires = serializers.SerializerMethodField()
    client_id = serializers.SerializerMethodField()
    client_secret = serializers.SerializerMethodField()
    token_flag = serializers.SerializerMethodField()
    flag = 0

    class Meta:
        model = User
        fields = ('client_id', 'client_secret', 'access_token', 'refresh_token', 'expires', 'token_flag')

    def get_access_token(self, obj):
        return AccessToken.objects.get(user=obj).token

    def get_refresh_token(self, obj):
        return RefreshToken.objects.get(user=obj).token

    def get_expires(self, obj):
        Comparetime = AccessToken.objects.get(user=obj).expires
        if Comparetime > timezone.now():
            LoginSerializer.flag = 0
        else:
            LoginSerializer.flag = 1
        return Comparetime

    def get_token_flag(self, obj):
        return LoginSerializer.flag
