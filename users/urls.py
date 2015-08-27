from django.conf.urls import url, patterns, include
from .views import UserViewSet, GroupViewSet
from django.contrib import admin
from rest_framework import routers
from . import views
admin.autodiscover()

router = routers.DefaultRouter()
router.register(r'users', UserViewSet, base_name='users')
router.register(r'groups', GroupViewSet)


urlpatterns = patterns('',
    url(r'^', include(router.urls)),
    url(r'^o/', include('oauth2_provider.urls', namespace='oauth2_provider')),
    #url(r'^admin/', include(admin.site.urls)),
    url(r'^login/$', views.Login.as_view(), name="login"),
    url(r'^sign_up/$', views.SignUp.as_view(), name="sign_up"),
    #url(r'^login1/$', views.Login1.as_view(), name="login1"),
)