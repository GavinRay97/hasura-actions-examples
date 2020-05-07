# Insider Docker container, print does not function properly
# Use logging.warning()
import logging
from utils import extract, generate_token
from graphql_client import Client
from flask import Flask, request, jsonify
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError


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


@app.route("/signup", methods=["POST"])
def signup_handler():
    values = request.get_json().get("input")
    (email, password) = (values["email"], values["password"])
    hashed_password = Password.hash(password)
    user_response = client.create_user(email, hashed_password)
    if user_response.get("errors"):
        return user_response
    else:
        user = extract(user_response, "insert_user_one")
        return user


@app.route("/login", methods=["POST"])
def login_handler():
    values = request.get_json().get("input")
    (email, password) = (values["email"], values["password"])
    user_response = client.find_user_by_email(email)
    user = extract(user_response, "user", single=True)
    try:
        Password.verify(user.get("password"), password)
        rehash_and_save_password_if_needed(user, password)
        return {"token": generate_token(user)}
    except VerifyMismatchError:
        return "Error: wrong password"


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
