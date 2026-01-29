from flask import Flask
app = Flask(__name__)

@app.route('/')
def home():
    return "<h1>🚀 Чат працює!</h1><p>Потім додам повний функціонал</p>"

if __name__ == '__main__':
    app.run()
