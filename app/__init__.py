from flask import Flask
import os

def create_app():
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-key")

    # register routes
    from .routes import bp as main_bp
    app.register_blueprint(main_bp)

    return app
