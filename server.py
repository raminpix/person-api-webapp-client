from os import environ as env
import base64
import requests
import json
import os
import re
from urllib.parse import quote_plus, urlencode
from flask import Flask, redirect, url_for, session, request, render_template
from flask_oauthlib.client import OAuth
from dotenv import find_dotenv, load_dotenv

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")
API_URL = env.get("PERSON_API_URL")
access_token = None
oauth = OAuth(app)

code_verifier = base64.urlsafe_b64encode(os.urandom(30)).decode("utf-8")
code_verifier = re.sub("[^a-zA-Z0-9]+", "", code_verifier)

remote = oauth.remote_app(
    'auth0',
    consumer_key=env.get("AUTH0_CLIENT_ID"),
    consumer_secret=env.get("AUTH0_CLIENT_ID"),
    request_token_params={'scope': 'openid profile email'},
    base_url='http://localhost:8080',
    access_token_method='POST',
    access_token_url=f'https://{env.get("AUTH0_DOMAIN")}/oauth/token',
    authorize_url=f'https://{env.get("AUTH0_DOMAIN")}/authorize'
)


# Controllers API
@app.route("/")
def home():

    is_logged_in = False
    if session.get("loggedInUser"):
        is_logged_in = True

    return render_template("home.html", logged_in=is_logged_in)


@app.route("/persons")
def get_all_persons():
    header = {'Authorization': 'Bearer ' + str(session.get("access_token"))}
    app.logger.info("header:" + str(header))
    response = requests.get(API_URL, headers=header)
    if response:
        all_persons = json.dumps(response.json(), indent=4)
    else:
        all_persons = None
    return render_template("persons.html", persons=all_persons)


@app.route("/callback", methods=["GET", "POST"])
def callback():
    code = request.args.get("code")
    payload = {
        "redirect_uri": "http://localhost:5000/",
        "client_id": env.get("AUTH0_CLIENT_ID"),
        "code_verifier": code_verifier,
        "grant_type": "authorization_code",
        "code": code
    }

    token_response = requests.post(
        f'https://{env.get("AUTH0_DOMAIN")}/oauth/token', headers=None, data=payload, auth=(env.get("AUTH0_CLIENT_ID"), env.get("APP_SECRET_KEY")),
    )
    response_json = token_response.json()
    access_token = str(response_json["access_token"])
    session["access_token"] = access_token
    session["loggedInUser"] = True
    return redirect("/")


@app.route('/login')
def login():
    return remote.authorize(callback=url_for('callback', _external=True))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://"
        + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=env.get("PORT", 5000))
