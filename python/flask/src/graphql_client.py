import requests
from dataclasses import dataclass


@dataclass
class Client:
    url: str
    headers: dict

    def run_query(self, query: str, variables: dict, extract=False):
        request = requests.post(
            self.url,
            headers=self.headers,
            json={"query": query, "variables": variables},
        )
        assert request.ok, f"Failed with code {request.status_code}"
        return request.json()

    find_user_by_email = lambda self, email: self.run_query(
        """
            query UserByEmail($email: String!) {
                user(where: {email: {_eq: $email}}, limit: 1) {
                    id
                    email
                    password
                }
            }
        """,
        {"email": email},
    )

    create_user = lambda self, email, password: self.run_query(
        """
            mutation CreateUser($email: String!, $password: String!) {
                insert_user_one(object: {email: $email, password: $password}) {
                    id
                    email
                    password
                }
            }
        """,
        {"email": email, "password": password},
    )

    update_password = lambda self, id, password: self.run_query(
        """
            mutation UpdatePassword($id: Int!, $password: String!) {
                update_user_by_pk(pk_columns: {id: $id}, _set: {password: $password}) {
                    password
                }
            }
        """,
        {"id": id, "password": password},
    )
