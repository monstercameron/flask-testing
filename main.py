import time
from flask import Flask, request, jsonify
import json
from jwt import (
    JWT,
    jwk_from_dict,
    jwk_from_pem,
)
import os
import subprocess
TEST_KEY = os.getenv("EMAIL")

# key gen public/private
# subprocess.call(["sudo","python","scale1.py"])
# -P "{os.getenv("PASSWORD")}"
private_key = f'ssh-keygen -t rsa -P "" -N "" -b 4096 -m PEM -f keys/jwtRS256.key <<< y'
public_key = f'ssh-keygen -e -m PEM -f keys/jwtRS256.key > keys/jwtRS256.key.pub'


def current_milli_time(): return int(round(time.time() * 1000))


app = Flask(__name__)
app.config['DEBUG'] = True


def Gen_JWT(payload):
    message = {
        'iat': current_milli_time(),
        'exp': current_milli_time() + 1000*60*5,  # +5 minutes
    }
    message.update(payload.get_json())
    with open(os.getenv("PRIKEY"), 'rb') as fh:
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
    with open(os.getenv("PUBKEY"), 'rb') as fh:
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
    return Gen_JWT(request)


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


@app.route('/generatekeys', methods=['GET'])
def Gen_Keys():
    try:
        resp = {
            "private": subprocess.getstatusoutput(private_key),
            "public": subprocess.getstatusoutput(public_key),
            "folder_output": os.listdir("keys")
        }
        return jsonify(resp)
    except:
        return 'couldn\'t generate key files'


if __name__ == '__main__':
    app.run()
