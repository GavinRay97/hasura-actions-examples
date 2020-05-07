import os
import jwt

HASURA_JWT_SECRET = os.getenv("HASURA_GRAPHQL_JWT_SECRET", "a-very-secret-secret")


def extract(result: dict, key: str, single: bool = False):
    """
    Utility function for extracting & formatting results from Hasura GraphQL requests
    """
    value = result["data"][key]
    return value[0] if single else value


# ROLE LOGIC FOR DEMO PURPOSES ONLY
# NOT AT ALL SUITABLE FOR A REAL APP
def generate_token(user) -> str:
    """
    Generates a JWT compliant with the Hasura spec, given a User object with field "id"
    """
    user_roles = ["user"]
    admin_roles = ["user", "admin"]
    is_admin = user["email"] == "admin@site.com"
    payload = {
        "https://hasura.io/jwt/claims": {
            "x-hasura-allowed-roles": admin_roles if is_admin else user_roles,
            "x-hasura-default-role": "admin" if is_admin else "user",
            "x-hasura-user-id": user["id"],
        }
    }
    token = jwt.encode(payload, HASURA_JWT_SECRET, "HS256")
    return token.decode("utf-8")
