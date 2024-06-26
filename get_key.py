#!/usr/bin/env python3

# From https://gadgetbridge.org/basics/pairing/fossil-server/?h=fossil+key#using-a-python-script
# Patched to ignore SSL errors (certificate not renewed).

import requests
import sys
import json
import base64

def die(s, r):
    print(s, file=sys.stderr)
    print(r.text, file=sys.stderr)
    sys.exit(1)

if len(sys.argv) != 3:
    print("Usage: %s username password" % (sys.argv[0]), file=sys.stderr)
    exit(1)

email = sys.argv[1]
password = sys.argv[2]
base_url = 'https://c.fossil.com/v2.1'  # use for fossil watches
#base_url = 'https://api.skagen.linkplatforms.com/v2.1'  # use for skagen watches
auth_url = base_url + '/rpc/auth/login'
keys_url = base_url + '/users/me/device-secret-keys'

# add in the email and password
auth_fields = {
    "email": email,
    "password": password,
    "clientId": "xxx",
}
# try to fetch the auth URL with this username / password
r = requests.post(auth_url, json=auth_fields, verify=False)
if r.status_code != 200:
    die("wrong username/password?", r)

token = json.loads(r.text).get("accessToken")
if not token:
    die("no access token in results?", r)

# now we can fetch the device keys using the bearer token
r = requests.get(keys_url, headers={
    "Authorization": "Bearer " + token,
}, verify=False)
if r.status_code != 200:
    die("access token not valid?", r)

devices = json.loads(r.text).get("_items")
if not devices:
    die("no devices in response?", r)

for dev in devices:
    devid = dev.get("id")
    key = dev.get("secretKey")
    if not key:
        die(devid + ": no secret key?", r)
    # only output the first 16 bytes of the secret key
    print(devid, base64.b64decode(key).hex()[0:32])
