from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate

# Serializers
from .serializers import (
    UserRegistrationSerializer,
    UserLoginSerializer,
    UserProfileSerializer,
)

# Renderers
from .renderers import UserDataRenderer


# Generate JWT manually
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        "refresh": str(refresh),
        "access": str(refresh.access_token),
    }


# Create your views here.
class UserRegistrationView(APIView):
    renderer_classes = [UserDataRenderer]

    def post(self, request, format=None):
        serializer = UserRegistrationSerializer(data=request.data)

        if serializer.is_valid(raise_exception=True):
            print(serializer.validated_data)
            user = serializer.save()
            token = get_tokens_for_user(user)

            return Response(
                {"msg": "Registration successful!", "tokens": token},
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserLoginView(APIView):
    renderer_classes = [UserDataRenderer]

    def post(self, request, format=None):
        serializer = UserLoginSerializer(data=request.data)

        if serializer.is_valid(raise_exception=True):
            email = serializer.data.get("email")
            password = serializer.data.get("password")
            user = authenticate(email=email, password=password)

            if user is not None:
                token = get_tokens_for_user(user)

                return Response(
                    {"msg": "Login successful!", "tokens": token},
                    status=status.HTTP_200_OK,
                )
            else:
                return Response(
                    {"errors": {"non_field_errors": ["Wrong email or password"]}},
                    status=status.HTTP_404_NOT_FOUND,
                )

        # print(serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class UserProfileView(APIView):
    renderer_classes = [UserDataRenderer]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, format=None):
        serializer = UserProfileSerializer(request.user)

        return Response(
            {"data": serializer.data}, status=status.HTTP_200_OK
        )
