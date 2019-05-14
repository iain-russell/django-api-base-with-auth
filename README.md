## Create main folder.

```
main directory name doesn't matter
```

## Make a virtual env

```
python3 -m venv myvenv
```

## Run venv

```
source myenv/bin/active
```

## Make requirements.txt file with requirements

```
Django>=2.1.3,<2.2.0
djangorestframework>=3.9.0,<3.10.0
psycopg2>=2.7.5,<2.8.0
Pillow>=5.3.0,<5.4.0
gunicorn>=19.9.0,<19.9.9
boto3>=1.9.11,<1.9.20
django-storages>=1.7.1,<1.8.0
flake8>=3.6.0,<3.7.0
```

## Install requirements

```
pip install -r requirements.txt
```

## Create main app directory

```
mkdir app
```

## Create django project

```
cd app
django-admin.py startproject app
```

## Create core app

```
python manage.py startapp core
```

## Create user app

```
python manage.py startapp user
```

## Create user tests
Make a test directory in /app/core
Add an `__init__.py` file in test directory so tests are recognized
Create test_models.py in /app/core/tests


Create test for user creation
```
from django.test import TestCase
from django.contrib.auth import get_user_model


class ModelTests(TestCase):

    def test_create_user_with_email_successful(self):
        """Test creating a new user with an email"""
        email = 'info@gmailcom'
        password = 'Testpass123'
        user = get_user_model().objects.create_user(
            email=email,
            password=password
        )

        self.assertEqual(user.email, email)
        self.assertTrue(user.check_password(password))
```
## Create user model
In /app/core/models.py create UserManager and User
User is the User model, UserManager is used for User creation

```
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, \
    PermissionsMixin

# Create your models here.


class UserManager(BaseUserManager):

    def create_user(self, email, password=None, **extra_fields):
        """Creates and saves a new user"""
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)

        return user


class User(AbstractBaseUser, PermissionsMixin):
    """ Custom user model that supports using email instead of username"""
    email = models.EmailField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
```

To change custom user model, add to the bottom of settings
```
AUTH_USER_MODEL = 'core.User'
```

## Make migrations
python manage.py makemigrations
python manage.py migrate

## Run tests and check syntax with flake8

python manage.py test && flake8

## Create test for normalizing email
Normalizing email changes `@GMAIL.`COM to `@gmail.com`
Add test to /app/core/tests/test_models
in ModelTests

```
    def test_new_user_email_normalized(self):
        """Test if new user email is normalize"""
        email = "test@GMAIL.com"
        user = get_user_model().objects.create_user(email, 'test123')

        self.assertEqual(user.email, email.lower())

```

The following uses our custom user model to create a user
```
get_user_model().objects.create_user(email, 'test123')
```

Change our user model to include a normalized email

from
```
self.model(email=email, **extra_fields)
```
to
```
user = self.model(email=self.normalize_email(email), **extra_fields)
```

# Create a test that checks user inputs an email on creation
Add to /app/core/tests

```
def test_new_user_invalid_email(self):
    """Test creating user with no email raises error"""
    with self.assertRaises(ValueError):
        get_user_model().objects.create_user(None, 'test123')
```
Add the following ValueError to the UserManager model
```
if not email:
  raise ValueError('Users must have an email' address')
```
```
class UserManager(BaseUserManager):

    def create_user(self, email, password=None, **extra_fields):
        """Creates and saves a new user"""
        if not email:
            raise ValueError('Users must have an email address')
        user = self.model(email=self.normalize_email(email), **extra_fields)
        user.set_password(password)
        user.save(using=self._db)

        return user
```

## Create test for superuser creation
In /app/core/tests/test_models  
ModelTests

```
def test_create_new_superuser(self):
    """Test creating a new superuser"""
    user = get_user_model().objects.create_superuser(
        'test@gmail.com',
        'test123'
    )

    self.assertTrue(user.is_superuser)
    self.assertTrue(user.is_staff)
```
## Add create superuser method to models
In /app/core/models UserManager
```
def create_superuser(self, email, password):
    """Creates and saves a new superuser"""
    user = self.create_user(email, password)
    user.is_staff = True
    user.is_superuser = True
    user.save(using=self._db)

    return user
```
#Admin
## Create admin tests
In /app/core/tests create test_admin.py

```
from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.urls import reverse


class AdminsiteTests(TestCase):

    def setUp(self):
        self.client = Client()
        self.admin_user = get_user_model().objects.create_superuser(
            email='admin@gmail.com',
            password='password123'
        )
        self.client.force_login(self.admin_user)
        self.user = get_user_model().objects.create_user(
            email='test@gmail.com',
            password='password123',
            name='Test user full name'
        )

    def test_users_listed(self):
        """Test that users are listed on user page"""
        url = reverse('admin:core_user_changelist')
        res = self.client.get(url)

        self.assertContains(res, self.user.name)
        self.assertContains(res, self.user.email)

    def test_user_change_page(self):
        """Test that user edit page works"""
        url = reverse('admin:core_user_change', args=[self.user.id])
        # /admin/core/user/1
        res = self.client.get(url)
        self.assertEqual(res.status_code, 200)

    def test_create_user_page(self):
        """Test the create user page works"""
        url = reverse('admin:core_user_add')
        res = self.client.get(url)

        self.assertEqual(res.status_code, 200)
```
## Edit /app/core/admin.py
Update which information is displayed on the admin page
[https://docs.djangoproject.com/en/2.2/ref/contrib/admin/](https://docs.djangoproject.com/en/2.2/ref/contrib/admin/)

```
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import gettext as _

from core import models
# Register your models here.


class UserAdmin(BaseUserAdmin):
    ordering = ['id']
    list_display = ['email', 'name']
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        (_('Personal Info'), {'fields': ('name',)}),
        (
            _('Permissions'),
            {'fields': ('is_active', 'is_staff', 'is_superuser')}
        ),
        (_('Important dates'), {'fields': ('last_login',)}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2')
        }),
    )


admin.site.register(models.User, UserAdmin)
```

# Setting up postgresql (incomplete)
Finish later

# Create user
## Create user tests  

In /app/user create test directory
Add ```__init__.py``` file so tests are recognized
Create a test_user_api.py file

```
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse

from rest_framework.test import APIClient
from rest_framework import status


CREATE_USER_URL = reverse('user:create')


def create_user(**param):
    return get_user_model().objects.create_user(**param)


class PublicUserApiTests(TestCase):
    """Test the users API (public)"""

    def setUp(self):
        self.client = APIClient()

    def test_create_valid_user_success(self):
        """Test creating user with valid payload is successful"""
        payload = {
            'email': 'test@gmail.com',
            'password': 'testpass',
            'name': 'Test name'
        }
        res = self.client.post(CREATE_USER_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_201_CREATED)
        user = get_user_model().objects.get(**res.data)
        self.assertTrue(user.check_password(payload['password']))
        self.assertNotIn('password', res.data)

    def test_user_exists(self):
        """Test checking that a user doesn't already exist"""
        payload = {'email': 'test@gmail.com', 'password': 'testpass'}
        create_user(**payload)

        res = self.client.post(CREATE_USER_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_password_too_short(self):
        """Test that the password is longer than 5 characters"""
        payload = {'email': 'test@gmail.com', 'password': 'pw'}
        res = self.client.post(CREATE_USER_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        user_exists = get_user_model().objects.filter(
            email=payload['email']
        ).exists()
        self.assertFalse(user_exists)
```

## Create user serializer
Make a serializers.py file in /app/user

```
from django.contrib.auth import get_user_model

from rest_framework import serializers


class UserSerializer(serializers.ModelSerializer):
    """Serializer for the users object"""

    class Meta:
        model = get_user_model()
        fields = ('email', 'password', 'name')
        extra_kwargs = {'password': {'write_only': True, 'min_length': 5 }}

    def create(self, validated_data):
        """Create a new user with encrypted password and return it"""
        return get_user_model().objects.create_user(**validated_data)
```

Create user view in /app/user/views.py

```
from rest_framework import generics

from user.serializers import UserSerializer


class CreateUserView(generics.CreateAPIView):
    """Create a new user in the system"""
    serializer_class = UserSerializer
```
Create urls.py in /app/user

```
from django.urls import path

from user import views


app_name = 'user'

urlpatterns = [
    path('create/', views.CreateUserView.as_view(), name='create'),
]
```
Add user urls to app urls in /app/urls.py
```
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/user/', include('user.urls')),
]
```
## Add token authentication to user
In /app/user/test_user_api.py add the following tests
```
TOKEN_URL = reverse('user:token')


def test_create_token_for_user(self):
        # Test that a token is created for the user
        payload = {'email': 'test@gmail.com', 'password': 'testpass'}
        create_user(**payload)
        res = self.client.post(TOKEN_URL, payload)

        self.assertIn('token', res.data)
        self.assertEqual(res.status_code, status.HTTP_200_OK)

    def test_create_token_invalid_credentials(self):
        # Test that token is not created if invalid credentials are given
        create_user(email='test@gmail.com', password='testpass')
        payload = {'email': 'test@gmail.com', 'password': 'wrong'}
        res = self.client.post(TOKEN_URL, payload)

        self.assertNotIn('token', res.data)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_token_no_user(self):
        # Test that the token is not created if user doesn't exist
        payload = {'email': 'test@gmail.com', 'password': 'testpass'}
        res = self.client.post(TOKEN_URL, payload)

        self.assertNotIn('token', res.data)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_token_missing_field(self):
        # Test the email and password are required
        payload = {'email': 'one', 'password': ''}
        res = self.client.post(TOKEN_URL, payload)
        self.assertNotIn('token', res.data)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
```
Add AuthTokenSerializer to app/user/serializers.py

```
from django.contrib.auth import get_user_model, authenticate
from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers


class AuthTokenSerializer(serializers.Serializer):
    # Serializers for the user
    email = serializers.CharField()
    password = serializers.CharField(
        style={'input_type': 'password'},
        trim_whitespace=False
    )


    def validate(self, attrs):
        """Validate and authenticate the user"""
        email = attrs.get('email')
        password = attrs.get('password')

        user = authenticate(
            request=self.context.get('request'),
            username=email,
            password=password
        )
        if not user:
            msg = _('Unable to authenticate with provided credentials')
            raise serializers.ValidationError(msg, code='authentication')

        attrs['user'] = user
        return attrs
```

Add the create token view to /app/users/views.py
The renderer class adds a ui for the api in the browser
```
from rest_framework import generics, authentication, permissions
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.settings import api_settings

from user.serializers import UserSerializer, AuthTokenSerializer


class CreateTokenView(ObtainAuthToken):
    # Create a new auth token for user
    serializer_class = AuthTokenSerializer
    renderer_classes = api_settings.DEFAULT_RENDERER_CLASSES
```
Add the create token path to the /app/users/urls.py
```
path('token/', views.CreateTokenView.as_view(), name='token'),
```

## Create user manager for users
Allows users to see and change their details (name, password, etc)

In /app/user/test_user_api.py add the following tests

The me url links to user personal info

```
ME_URL = reverse('user:me')


def test_retrieve_user_unauthorized(self):
    """Test that authentication is required for users"""
    res = self.client.get(ME_URL)

    self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)


    class PrivateUserApiTests(TestCase):
        """Test API requests that reqiure authentication"""

        def setUp(self):
            self.user = create_user(
                email='test@gmail.com',
                password='testpass',
                name='name'
            )
            self.client = APIClient()
            self.client.force_authenticate(user=self.user)

        def test_retrieve_profile_success(self):
            """Test retrieving profile for logged in user"""
            res = self.client.get(ME_URL)

            self.assertEqual(res.status_code, status.HTTP_200_OK)
            self.assertEqual(res.data, {
                'name': self.user.name,
                'email': self.user.email
            })

        def test_post_me_not_allowed(self):
            """Test that POST is not allowed on the me url"""
            res = self.client.post(ME_URL, {})

            self.assertEqual(res.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

        def test_update_user_profile(self):
            """Test that updating the user profile for authenticated user"""
            payload = {'name': 'new name', 'password': 'newpassword'}

            res = self.client.patch(ME_URL, payload)

            self.user.refresh_from_db()
            self.assertEqual(self.user.name, payload['name'])
            self.assertTrue(self.user.check_password(payload['password']))
            self.assertEqual(res.status_code, status.HTTP_200_OK)
```
Add the ManageUserView to /app/users/views.py
The get_object is customized to return the request.user
```
from rest_framework import generics, authentication, permissions
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.settings import api_settings

from user.serializers import UserSerializer, AuthTokenSerializer


class ManageUserView(generics.RetrieveUpdateAPIView):
    """Manage the authenticated user"""
    serializer_class = UserSerializer
    authentication_classes = (authentication.TokenAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)

    def get_object(self):
        """Retrieve and return authenication user"""
        return self.request.user
```
In /app/user/serializers.py add a user info update function for the UserSerializer
```
    def update(self, instance, validated_data):
        """Update a user, setting the password correctly and return it"""
        password = validated_data.pop('password', None)
        user = super().update(instance, validated_data)

        if password:
            user.set_password(password)
            user.save()

        return user
```
Add the ManageUserView path to /app/user/urls.py
```
path('me/', views.ManageUserView.as_view(), name='me'),
```
