# IMHere

Login Done
API ENdPoint

Login

Use this endpoint to obtain user authentication token.

GET

URL: /login

request

data:

username

password

in Basic Authorization format in header

response

status: HTTP_200_OK (success)

data:

clientid,client_secret,expire time,auth_token

