from flask import Flask, request, jsonify
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt
import spacy

app = Flask(__name__)

Api = Api(app)

# client = MongoClient("mongodb://db:27017")
client = MongoClient('localhost:27017')
db = client.SimilarityDB
users = db["Users"]

def UserExist(username):
    if users.find({"Username":username}).count() == 0:
        return False
    else:
        return True

class Register(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]

        if UserExist(username):
            retJson = {
                "Status" : 301,
                "Message":"Username already exists!, Choose the othe username!"
            }
            return jsonify(retJson)

        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        users.insert({
            "Username": username,
            "Password" : hashed_pw,
            "Tokens": 6
        })
        retJson = {
            "Status": 200,
            "Message": "You have successfully signed up for API"
        }
        return jsonify(retJson)

def verifyPw(username, password):
    if not UserExist(username):
        return False

    hashed_pw = users.find({
        "Username": username,
    })[0]["Password"]

    if bcrypt.hashpw(password.encode('utf-8'), hashed_pw) == hashed_pw:
        return True
    else:
        return False

def countTokens(username):
    tokens = users.find({
        "Username": username
    })[0]["Tokens"]
    return tokens


class Detect(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]
        text1 = postedData["text1"]
        text2 = postedData["text2"]

        if not UserExist(username):
            retJson = {
                "Status" : 301,
                "Message": "Invalid Username"
            }
            return jsonify(retJson)

        correct_pw = verifyPw(username, password)

        if not correct_pw:
            retJson = {
                "Status" : 302,
                "Message": "Invalid Password"
            }
            return jsonify(retJson)

        num_tokens = countTokens(username)

        if num_tokens <= 0:
            retJson = {
                "Status" : 302,
                "Message": "You are run out of tokens, please refill"
            }
            return jsonify(retJson)

        # Calculate the edit distance
        nlp = spacy.load("en_core_web_sm")
        text1 = nlp(text1)
        text2 = nlp(text2)

        # Ratio is between [0,1] , closer to 1 is more the similarity
        ratio = text1.similarity(text2)

        retJson = {
            "Status" : 200,
            "Similarity Ration": ratio,
            "Message": "Similarity is Calculateed"
        }

        current_tokens = countTokens(username)
        users.update({
            "Username": username,
        },{
            "$set":{
                "Tokens":current_tokens - 1
            }
        })

        return jsonify(retJson)

class Refill(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]
        refill_amount = postedData["refill"]

        if not UserExist(username):
            retJson = {
                "Status" : 301,
                "Message": "Invalid Username"
            }
            return jsonify(retJson)

        # correct_pw = verifyPw(username, password)
        correct_pw = "abc"

        if correct_pw != password:
            retJson = {
                "Status" : 302,
                "Message": "Invalid admin password"
            }
            return jsonify(retJson)

        # Refill the Tokens
        current_tokens = countTokens(username)
        users.update({
            "Username": username,
        },{
            "$set":{
                "Tokens":current_tokens + refill_amount
            }
        })
        retJson = {
            "Status" : 200,
            "Message": "Refilled successfully"
        }

        return jsonify(retJson)

Api.add_resource(Register, "/register")
Api.add_resource(Detect, "/detect")
Api.add_resource(Refill, "/refill")


if __name__ == "__main__":
    app.run(host="0.0.0.0")
