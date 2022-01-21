#!/usr/bin/env python3
"""
Contains methods and attributes
for authentication
"""
from bcrypt import hashpw, gensalt, checkpw
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import InvalidRequestError
import uuid
from typing import Union


def _hash_password(password: str) -> bytes:
    """
    Encrypts password.
    Args:
        password: The password to be encrypted.
    Returns:
        bytes
    """
    return hashpw(password.encode(), gensalt())


def _generate_uuid() -> str:
    """
    Generates uuids

    Returns:
        str: The generated UUID.
    """
    return str(uuid.uuid4())


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

    def valid_login(self, email: str, password: str) -> bool:
        """
        Validates login.
        Args:
            email: The user's email.
            password: The user's password.
        Returns:
            bool: True if the login is valid else False.
        """
        if not email or not password:
            return False
        try:
            existing_user = self._db.find_user_by(email=email)
            hashed_password = existing_user.hashed_password
            return checkpw(password.encode(),
                           hashed_password.encode('utf-8'))
        except (NoResultFound, InvalidRequestError):
            return False

    def create_session(self, email: str) -> str:
        """
        Creates a user session.
        Args:
            email: The user's email.
        Returns:
            str: The session id.
        """
        try:
            existing_user = self._db.find_user_by(email=email)
            session_id = _generate_uuid()
            self._db.update_user(existing_user.id, session_id=session_id)
            return session_id
        except (NoResultFound, ValueError):
            return None

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """
        Gets the user from a session id.
        Args:
            session_id: The session id.
        Returns:
            User: The user object
            or None.
        """
        if not session_id:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """
        Destroys a user session.
        Args:
            user_id: The user's id.
        """
        try:
            self._db.update_user(user_id, session_id=None)
        except ValueError:
            pass

    def get_reset_password_token(self, email: str) -> str:
        """
        Gets a reset password token.
        Args:
            Email: The user's email.
        Raises:
            ValueError: If the user does not exist.
        Returns:
            str: The reset password token.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError
        token = _generate_uuid()
        self._db.update_user(user.id, reset_token=token)
        return token

    def update_password(self, reset_token: str, password: str) -> None:
        """
        Updates the user's password
        Args:
            reset_token: The reset password token.
            password: The new password.
        Returns:
            None
        Raises:
            ValueError: If the reset token is invalid.
        """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            hashed_password = _hash_password(password).decode('utf-8')
            self._db.update_user(user.id, hashed_password=hashed_password,
                                 reset_token=None)
        except NoResultFound:
            raise ValueError
