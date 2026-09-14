import os
from flask import Flask
from .models import init_db


def create_app():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    app = Flask(__name__,
                template_folder=os.path.join(root, 'templates'),
                static_folder=os.path.join(root, 'static'))
    app.config['SECRET_KEY'] = 'oauth2-lab-neon-x'
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    init_db()
    from .routes import bp
    app.register_blueprint(bp)
    return app