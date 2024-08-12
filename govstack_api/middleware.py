import os
import logging 
from functools import wraps
from types import SimpleNamespace
from unittest import mock

from graphene import Schema
from graphene.test import Client

from django.apps import apps
from django.contrib.auth import get_user_model
from django.http import HttpResponse
from core.schema import Query as CoreQuery, Mutation as CoreMutation

logger = logging.getLogger(__name__)

def authenticate_decorator(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        config = apps.get_app_config('govstack_api')
        im_client = config.IM_CLIENT
        im_header = request.META.get('HTTP_INFORMATION_MEDIATOR_CLIENT')
        if im_header != im_client:
            return HttpResponse('Unauthorized', status=401)
        else:
            # self.authenticate_user(request)
            pass

        return view_func(request, *args, **kwargs)
    return _wrapped_view


class InformationMediatorMiddleware:
    """
    Used to authenticate request using Information Mediator instead of standard JWT authentication.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.headers.get('Information-Mediator-Client', None):
            config = apps.get_app_config('govstack_api')
            im_client = config.IM_CLIENT
            im_header = request.META.get('HTTP_INFORMATION_MEDIATOR_CLIENT')
            # TODO: Temporary comparison awaiting information mediator setup.
            # This check will likely be updated when the setup is complete.
            if im_header != im_client:
                return HttpResponse('Unauthorized', status=401)
            else:
                self.authenticate_user(request)
        response = self.get_response(request)
        return response

    def get_client(self, schema, query, mutation):
        return Client(schema=schema(query=query, mutation=mutation))

    def get_context(self, request):
        if hasattr(request, 'user') and request.user.is_authenticated:
            context = SimpleNamespace(user=request.user)
        else:
            context = SimpleNamespace(user=None)
        return context

    # TODO: This mutation-based login approach is a temporary solution. In the future,
    # we should integrate with an external authentication service. The usage of
    # this mutation for login purposes should be phased out once that integration
    # is complete and has been tested to work reliably.
    def authenticate_user(self, request):
        client = self.get_client(Schema, CoreQuery, CoreMutation)
        username = os.getenv('login_openIMIS')
        password = os.getenv('password_openIMIS')
        mutation = f'''
          mutation {{
              tokenAuth(username: "{username}", password: "{password}") {{
                  token
                  refreshExpiresIn
              }}
          }}
          '''
        context = self.get_context(request)
        try:
            result = client.execute(mutation, context=context)
        except Exception as e:
            print(f"Exception occurred: {e}")
            return None
        if 'data' in result and 'tokenAuth' in result['data'] and 'token' in result['data']['tokenAuth']:
            token = result['data']['tokenAuth']['token']
            if token:
                request.META['HTTP_AUTHORIZATION'] = f'Bearer {token}'
                User = get_user_model()
                user = User.objects.get(username=username)
                request.user = user
        return result

class ContentTypeMiddleware:
    """
    Digital Registry specification explicitly request content type header to be of `application/json`. Therefore,
    standard header with extra information about charset is replaced.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        try:
            # Check if the response is from a specific app
            view_module = request.resolver_match.func.__module__
        except Exception as e: 
            logger.exception(F'Invalid resolve_match format for request {request}.')
            return response
            
        if "govstack_api" in view_module and response['Content-Type'] == 'application/json; charset=utf-8':
            response['Content-Type'] = 'application/json'

        return response
