import os
from flask import Flask


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "dev-key-change-me")
    app.config["MAX_CONTENT_LENGTH"] = int(
        os.environ.get("MAX_CONTENT_LENGTH", 16 * 1024 * 1024)
    )
    app.config["UPLOAD_FOLDER"] = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "uploads"
    )

    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    from app.routes import main_bp

    app.register_blueprint(main_bp)

    return app
