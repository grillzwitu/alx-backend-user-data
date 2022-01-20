#!/usr/bin/env python3
"""
Basic Flask app.
"""
from flask import Flask, jsonify, request
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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
