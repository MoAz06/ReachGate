"""Demo application entry point. Declared in reachgate.yml as the attack surface."""

from flask import Flask

from routes.orders import orders_bp

app = Flask(__name__)
app.register_blueprint(orders_bp)


if __name__ == "__main__":
    app.run()
