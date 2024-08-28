import json
import pyrebase

config = {
  "apiKey": "AIzaSyCR2Al5_9U5j6UOhqu0HCDS0jhpYfa2Wgk",
  "authDomain": "crackme-1b52a.firebaseapp.com",
  "databaseURL": "https://crackme-1b52a-default-rtdb.firebaseio.com",
  "storageBucket": "crackme-1b52a.appspot.com"
}

firebase = pyrebase.initialize_app(config)
auth = firebase.auth()

user = auth.sign_in_with_email_and_password("admin@sekai.team", "s3cr3t_SEKAI_P@ss")
uid = user.get("localId")

db = firebase.database()

path = db.child("users").child(uid).child("flag")
print(path.get(user['idToken']).val())

# SEKAI{15_React_N@71v3_R3v3rs3_H@RD???}