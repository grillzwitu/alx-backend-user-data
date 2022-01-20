#!/usr/bin/env python3
"""
Contains methods and attributes
for authentication
"""
from bcrypt import hashpw, gensalt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound


def _hash_password(password: str) -> bytes:
    """
    Encrypts password.
    Args:
        password: The password to be encrypted.
    Returns:
        bytes
    """
    return hashpw(password.encode(), gensalt())


class Auth:
    """
    Auth class to interact with the authentication database.
    Attributes:
        _db: The database object.
    """

    def __init__(self):
        """
        Constructor for the Auth class.
        """
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """
        Registers a user in the database.
        Args:
            email: The user's email.
            password: The user's password.
        Raises:
            ValueError: If the user already exists.
        Returns:
            User: The user object.
        """
        try:
            existing_user = self._db.find_user_by(email=email)
            if existing_user:
                raise ValueError("User {} already exists".format(email))
        except NoResultFound:
            hashed_password = _hash_password(password).decode('utf-8')
            new_user = self._db.add_user(email, hashed_password)
            return new_user
