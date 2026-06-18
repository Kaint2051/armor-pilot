import logging
import sys

from flask import Flask, make_response, render_template

from .product import PRODUCT_NAME, PRODUCT_TAGLINE


def create_app() -> Flask:
    app = Flask(__name__)

    # Single stdout handler for all loggers (Kubernetes log collectors read stdout)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(
        "[%(asctime)s] [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    ))
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    if not root.handlers:
        root.addHandler(handler)

    from .routes.api import api_bp
    app.register_blueprint(api_bp)

    from . import db as _db
    _db.init_db()

    @app.route("/")
    def index():
        resp = make_response(render_template(
            "index.html",
            product_name=PRODUCT_NAME,
            product_tagline=PRODUCT_TAGLINE,
        ))
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        return resp

    return app


app = create_app()
