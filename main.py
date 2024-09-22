import base64
import uuid
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, abort
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwcrypto import jwk, jwt

keys = {}
expiredKeys = {}
currentKeyID = None

app = Flask(__name__)

"""Generate RSA pair and return keys"""
def generateKeyPair():
    privateKey = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = 2048
    )

    unencrypted_privateKey = privateKey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm = serialization.NoEncryption()
    )

    pem_public_key = privateKey.public_key().public_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return unencrypted_privateKey, pem_public_key

"""Generate metadata (KID/expiry)"""
def create_key_metadata(expiry_days = 365):
    key_id = str(uuid.uuid4())
    expiry_timestamp = (datetime.utcnow() + timedelta(days = expiry_days)).isoformat() + 'Z'
    return{
        'kid' : key_id,
        'expiry' : expiry_timestamp
    }

"""Create and store RSA key pairs/expired key"""
def initialize_keys():
    global currentKeyID
    unencrypted_private_key, public_key = generateKeyPair()

    metadata = create_key_metadata(expiry_days = 365)
    currentKeyID = metadata['kid']

    #metadata for current key
    keys[currentKeyID] = {
        'private_key' : unencrypted_private_key,
        'public_key' : public_key,
        'metadata' : metadata
    }

"""Create a test expired key pair"""
def create_expired_key():
    unencrypted_private_key, public_key = generateKeyPair()

    #sets proper data for "expired"
    metadata = create_key_metadata(expiry_days=-1)
    expired_key_id = metadata['kid']

    #list of metadata for expired keys
    expiredKeys[expired_key_id] = {
        'private_key' : unencrypted_private_key,
        'public_key' : public_key,
        'metadata' : metadata
    }

initialize_keys()
create_expired_key()

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    """Serve public keys using JWKS"""
    now = datetime.utcnow().replace(tzinfo=None) #get current time
    jwks = {'keys': []}

    try:
        for key_id, key_info in keys.items():
            #convert expiry to timezone-aware
            expiry_date = datetime.fromisoformat(key_info['metadata']['expiry'].replace('Z', '+00:00')).replace(tzinfo=None)
            #check if key is not expired
            if now < expiry_date:
                #load public key
                public_key = serialization.load_pem_public_key(key_info['public_key'])
                jwk_key = jwk.JWK.from_pem(key_info['public_key']) #PEM to JWK

                jwks['keys'].append({
                    'kid':key_id,
                    'kty':'RSA',
                    'alg': 'RS256',
                    'use': 'sig',
                    'n': base64.urlsafe_b64encode(public_key.public_numbers().n.to_bytes((public_key.public_numbers().n.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip('='),
                    'e': base64.urlsafe_b64encode(public_key.public_numbers().e.to_bytes((public_key.public_numbers().e.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip('=') #converts strings to bytes for proper use
                })
    except Exception as e:
        app.logger.error(f"Error generating JWKS: {e}")
        abort(500, description="Internal server error")

    return jsonify(jwks)

@app.route('/auth', methods=['POST'])
def auth():
    """Return JWT based on requests"""
    expired = request.args.get('expired')
    try:
        if expired:
            expired_id = next(iter(expiredKeys), None)
            if not expired_id or expired_id not in expiredKeys:
                abort(404, description='Expired key not found')
            key_info = expiredKeys[expired_id]
        else:
            if not keys or currentKeyID not in keys:  # Check if keys is empty or the currentKeyID is not available
                abort(404, description='Current key not found')
            key_info = keys[currentKeyID]

        private_key = serialization.load_pem_private_key(
            key_info['private_key'],
            password=None
        )
        key = jwk.JWK.from_pem(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

        token = create_jwt(key, key_info['metadata']['kid'], expiry_days=-1 if expired else 1)
        return jsonify({"token": token})
    except Exception as e:
        app.logger.error(f"Error generating JWT: {e}")
        abort(500, description="Internal server error")



def create_jwt(key, key_id, expiry_days = 365):
    "Create JWT using key and expiry"
    claims = {
        "sub": "user",
        "exp": (datetime.utcnow() + timedelta(days = expiry_days)).timestamp()
    }
    token = jwt.JWT(header={"alg": "RS256", "kid":key_id}, claims = claims)
    token.make_signed_token(key)
    return token.serialize()

#run server
if __name__ == '__main__':
    app.run(port = 8080, debug = True)