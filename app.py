from flask import Flask,render_template
from sqlalchemy import true


app = Flask(__name__)

@app.route('/')

def home():
    name = "Puneet"
    return render_template('index.html',name = name)


if __name__ == "__main__":
    app.run(debug=True)
