import os
import logging
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

    # Auto-load device configs from configs/ directory
    from app.config_loader import load_configs

    with app.app_context():
        loaded = load_configs()
        if loaded:
            logging.getLogger(__name__).info(
                "Pre-loaded %d device config(s) from configs/ directory", len(loaded)
            )

    return app
