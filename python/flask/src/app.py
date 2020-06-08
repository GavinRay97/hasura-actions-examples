# Insider Docker container, print does not function properly
# Use logging.warning()
import json
import logging
from utils import extract, generate_token
from graphql_client import Client
from flask import Flask, request, jsonify
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from typing import Optional
from dataclasses import dataclass, asdict

HASURA_URL = "http://graphql-engine:8080/v1/graphql"
HASURA_HEADERS = {"X-Hasura-Admin-Secret": "your-secret"}

Password = PasswordHasher()
client = Client(url=HASURA_URL, headers=HASURA_HEADERS)


def rehash_and_save_password_if_needed(user, plaintext_password):
    """
    Whenever your Argon2 parameters – or argon2-cffi’s defaults! – 
    change, you should rehash your passwords at the next opportunity.
    The common approach is to do that whenever a user logs in, since 
    that should be the only time when you have access to the cleartext password.
    Therefore it’s best practice to check – and if necessary rehash –
    passwords after each successful authentication.
    """
    if Password.check_needs_rehash(user["password"]):
        client.update_password(user["id"], Password.hash(plaintext_password))


app = Flask(__name__)


@dataclass
class RequestMixin:
    @classmethod
    def from_request(cls, request):
        """
        Helper method to convert an HTTP request to Dataclass Instance
        """
        values = request.get("input")
        return cls(**values)

    def to_json(self):
        return json.dumps(asdict(self))


@dataclass
class CreateUserOutput(RequestMixin):
    id: int
    email: str
    password: str


@dataclass
class JsonWebToken(RequestMixin):
    token: str


@dataclass
class AuthArgs(RequestMixin):
    email: str
    password: str


@app.route("/signup", methods=["POST"])
def signup_handler():
    args = AuthArgs.from_request(request.get_json())
    hashed_password = Password.hash(args.password)
    user_response = client.create_user(args.email, hashed_password)
    if user_response.get("errors"):
        return {"message": user_response["errors"][0]["message"]}, 400
    else:
        user = user_response["data"]["insert_user_one"]
        return CreateUserOutput(**user).to_json()


@app.route("/login", methods=["POST"])
def login_handler():
    args = AuthArgs.from_request(request.get_json())
    user_response = client.find_user_by_email(args.email)
    user = user_response["data"]["user"][0]
    try:
        Password.verify(user.get("password"), args.password)
        rehash_and_save_password_if_needed(user, args.password)
        return JsonWebToken(generate_token(user)).to_json()
    except VerifyMismatchError:
        return {"message": "Invalid credentials"}, 401


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
