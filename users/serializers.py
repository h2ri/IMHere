from django.contrib.auth.models import User,Group
from models import MyUser
from rest_framework import serializers
from .models import MyUser
from oauth2_provider.models import Application, AccessToken, RefreshToken
from datetime import datetime
import httplib
import urllib
from django.utils import timezone
# first we define the serializers

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
        fields = ('username','password','client_id','client_secret')
        #write_only_fields = ('password',)
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
    referesh_token = serializers.SerializerMethodField()
    expires = serializers.SerializerMethodField()
    client_id = serializers.SerializerMethodField()
    client_secret = serializers.SerializerMethodField()
    print client_id
    class Meta:
        model = User
        fields = ('client_id','client_secret','access_token','referesh_token','expires')
    #To get referesh token
    ''' def getRefreshToken():
        conn = httplib.HTTPConnection("127.0.0.1:8000")
        url =  "/o/token/"
        headersMap = {
                      "Content-Type": "application/x-www-form-urlencoded",
                      };
        data = {'refresh_token':str('refresh_token'),'grant_type':str('refresh_token'),'client_id':str('client_id'),'client_secret':str('client_secret')
            }
        requestUrl = url + "?" + urllib.urlencode(data)
        conn.request("POST", requestUrl, headers=headersMap)
        response = conn.getresponse()
        print response
        if response.status == 200:
            data = response.read()
            result = json.loads( data )
            return result
        else:
            print response.status
    '''
    def get_access_token(self,obj):
        return AccessToken.objects.get(user=obj).token
        
    def get_referesh_token(self,obj):
        return RefreshToken.objects.get(user=obj).token
        
    def get_expires(self,obj):       
        Comparetime = AccessToken.objects.get(user=obj).expires
        if Comparetime > timezone.now():
            pass
        else:
            print "got it"
        return Comparetime
    