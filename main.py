import time
from flask import Flask, request, jsonify
import json
from jwt import (
    JWT,
    jwk_from_dict,
    jwk_from_pem,
)
import os
TEST_KEY = os.getenv("EMAIL")


def current_milli_time(): return int(round(time.time() * 1000))


app = Flask(__name__)
app.config['DEBUG'] = True


def Gen_JWT():
    message = {
        'iss': 'https://example.com/',
        'sub': 'yosida95',
        'iat': current_milli_time(),
        'exp': current_milli_time() + 1000*60*5,  # +5 minutes
    }
    with open(os.getenv("TESTPRIKEY"), 'rb') as fh:
        signing_key = jwk_from_pem(fh.read())
    jwt = JWT()
    token = jwt.encode(message, signing_key, 'RS256')
    # build response object
    resp = jsonify(state=0, msg='success', data={'token': token})
    # attach cookies
    resp.set_cookie('token', token, secure=True)
    return resp


def Is_Valid_JWT(data):
    # expects json {"token":"<JWT>"}
    with open(os.getenv("TESTPUBKEY"), 'rb') as fh:
        verifying_key = jwk_from_pem(fh.read())
    jwt = JWT()
    try:
        return jsonify(jwt.decode(data, verifying_key))
    except:
        return 'can\'t decode jwt'


@app.route('/')
def hello_world():
    return TEST_KEY


@app.route('/jwt', methods=['POST'])
def Encode_JWT():
    return Gen_JWT()


@app.route('/jwt', methods=['GET'])
def Decode_JWT():
    myToken = request.get_json()
    # return 'test'
    return Is_Valid_JWT(myToken['token'])


@app.route('/cookie', methods=['GET'])
def Cookie_Value():
    try:
        token = request.cookies.get('token')
        return token
    except:
        return 'test'

if __name__ == '__main__':
    app.run()
