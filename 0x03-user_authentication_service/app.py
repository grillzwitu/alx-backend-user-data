#!/usr/bin/env python3
"""
Basic Flask app.
"""
from crypt import methods
from flask import Flask, jsonify, request, abort, redirect
from sqlalchemy import false
from auth import Auth
from typing import Union

app = Flask(__name__)
AUTH = Auth()


@app.route('/', methods=['GET'], strict_slashes=False)
def base() -> str:
    """
    Base route
    Returns:
        str: json payload
    """
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'], strict_slashes=False)
def new_user() -> Union[str, tuple]:
    """
    POST method /users route
    Registers new users with email and password,
    or checks if the email is already registered
    Return:
      - json payload
    """

    # Get data from form request,
    # convert to json with request.get_json() for the body
    email = request.form.get("email")
    password = request.form.get("password")

    try:
        new_user = AUTH.register_user(email, password)
        if new_user is not None:
            return jsonify({
                "email": new_user.email,
                "message": "user created"
            })
    except ValueError:
        return jsonify({
            "message": "email already registered"
            }), 400


@app.route('/sessions', methods=['POST'], strict_slashes=False)
def login() -> str:
    """
    POST method, route /sessions
    Creates new user session, stores the session id as a cookie

    Return:
      - json payload
    """

    # Get data from form request,
    # convert to json with request.get_json() for the body
    email = request.form.get("email")
    password = request.form.get("password")
    valid_login = AUTH.valid_login(email, password)

    if not valid_login:
        abort(401)
    session_id = AUTH.create_session(email)
    response_content = {"email": email, "message": "logged in"}
    response = jsonify(response_content)
    response.set_cookie("session_id", session_id)
    return response


@app.route('/sessions', methods=['DELETE'], strict_slashes=False)
def logout():
    """
    method DELETE, route /sessions
    Destroys a user session by finding the session_id key in the cookie
    Return:
      Redirects the user to the Base route (GET /)
    """
    the_cookie = request.cookies.get("session_id", None)
    user = AUTH.get_user_from_session_id(the_cookie)
    if the_cookie is None or user is None:
        abort(403)
    AUTH.destroy_session(user.id)
    return redirect('/')


@app.route('/profile', methods=['GET'], strict_slashes=False)
def profile() -> str:
    """
    method GET, route /profile
    Finds the user using session id
    Return:
        - User's email with status 200
        - 403 error if session id is invalid
    """
    user_cookie = request.cookies.get("session_id", None)
    if user_cookie is None:
        abort(403)
    user = AUTH.get_user_from_session_id(user_cookie)
    if user is None:
        abort(403)
    return jsonify({"email": user.email}), 200


@app.route('/reset_password', methods=['POST'], strict_slashes=False)
def get_reset_password_token() -> tuple:
    """ method POST, route /reset_password
        Args
            - The user's email
        Return:
            - json payload
            - 403 if email not registered
    """
    email = request.form.get('email')
    try:
        token = AUTH.get_reset_password_token(email)
        return jsonify({"email": email,
                        "reset_token": token}), 200
    except ValueError:
        abort(403)


@app.route('/reset_password', methods=['PUT'], strict_slashes=False)
def update_password() -> tuple:
    """
    method PUT, route /reset_password
    Args
        - email
        - reset_token
        - new_password
    Return:
        - the updated password
        - 403 if token is invalid
    """
    email = request.form.get('email')
    reset_token = request.form.get('reset_token')
    new_password = request.form.get('new_password')

    try:
        AUTH.update_password(reset_token, new_password)
        return jsonify({"email": email, "message": "Password updated"}), 200
    except ValueError:
        abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
