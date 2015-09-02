import httplib
import urllib
import json

from django.contrib.auth.models import Group
from rest_framework import permissions, viewsets, generics
from oauth2_provider.ext.rest_framework import TokenHasReadWriteScope, TokenHasScope

from rest_framework.authentication import BasicAuthentication

from rest_framework.response import Response

from rest_framework.views import APIView

from rest_framework import status

from .models import MyUser
from .serializers import UserSerializer, GroupSerializer, SignUpSerializer, LoginSerializer
from .permissions import IsAuthenticatedOrCreate


class UserViewSet(viewsets.ModelViewSet):
    permission_classes = [permissions.IsAuthenticated, TokenHasReadWriteScope]
    queryset = MyUser.objects.all()
    # permission_classes = (permissions.AllowAny,)

    serializer_class = UserSerializer

    def get_queryset(self):
        if self.request.user.is_superuser:
            return MyUser.objects.all()
        else:
            return MyUser.objects.filter(id=self.request.user.id)


def getAuthToken(creds, password):
    conn = httplib.HTTPConnection("127.0.0.1:8000")
    url = "/o/token/"
    headersMap = {
        "Content-Type": "application/x-www-form-urlencoded",
    };
    data = {'username': str(creds["email"]), 'password': str(password), 'grant_type': str('password'),
            'client_id': str(creds["client_id"]), 'client_secret': str(creds["client_secret"])
            }

    requestUrl = url + "?" + urllib.urlencode(data)
    conn.request("POST", requestUrl, headers=headersMap)
    response = conn.getresponse()
    if response.status == 200:
        data = response.read()
        result = json.loads(data)
        return result
    else:
        data1 = response.read()
        result1 = json.loads(data1)
        return result1


class GroupViewSet(viewsets.ModelViewSet):
    permission_classes = [permissions.IsAuthenticated, TokenHasScope]
    required_scopes = ['groups']
    queryset = Group.objects.all()
    serializer_class = GroupSerializer


class SignUp(generics.CreateAPIView):
    queryset = MyUser.objects.all()
    serializer_class = SignUpSerializer
    permission_classes = (IsAuthenticatedOrCreate,)

    def create(self, request, *args, **kwargs):

        password = request.POST.get('password', '')
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            self.object = serializer.save()
            creds = serializer.data
            token = getAuthToken(creds, password)
            return Response(token, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Login
# username and password
# return ClientID ClientSecret AccessToken RefereshToken ExpireTime TokenFlag
class Login(generics.ListAPIView):
    # queryset = MyUser.objects.all()
    serializer_class = LoginSerializer
    authentication_classes = (BasicAuthentication,)

    def get_queryset(self):
        return [self.request.user]

    def list(self, request, *args, **kwargs):
        response = generics.ListAPIView.list(self, request, *args, **kwargs)
        data1 = response.data
        if data1[0]['token_flag'] == 1:
            if getAuthFromRefreshToken(data1[0]):
                data2 = generics.ListAPIView.list(self, request, *args, **kwargs).data
                data2[0]['refresh_token'] = " "
                return Response(data2, status=status.HTTP_200_OK)
        else:
            data1[0]['refresh_token'] = " "
            return Response(data1, status=status.HTTP_201_CREATED)


# To Obtain Refresh Token if Access Token Expired 
# /o/token for refresh
def getAuthFromRefreshToken(credtoken):
    # print credtoken['access_token']
    conn = httplib.HTTPConnection("127.0.0.1:8000")
    url = "/o/token/"
    headersMap = {"Content-Type": "application/x-www-form-urlencoded",
                  };
    data = {'refresh_token': str(credtoken['refresh_token']), 'grant_type': str('refresh_token'),
            'client_id': str(credtoken['client_id']), 'client_secret': str(credtoken['client_secret'])
            }
    requestUrl = url + "?" + urllib.urlencode(data)
    conn.request("POST", requestUrl, headers=headersMap)
    response = conn.getresponse()
    if response.status == 200:
        return 1


# Forgot Password
class PasswordReset(APIView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request):
        data = {}
        print request.data['token']
        print self.request.user.id
        return Response(data,status=status.HTTP_200_OK)
