import os
import sys
import threading
import webbrowser

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.models import seed
from app import create_app

PORT = 5090


def main():
    seed()
    app = create_app()
    threading.Timer(1.5, lambda: webbrowser.open(f'http://127.0.0.1:{PORT}')).start()
    print(f'[OAuth2 Deep Lab] http://127.0.0.1:{PORT} (CTRL+C untuk stop)')
    app.run(host='127.0.0.1', port=PORT, debug=False, use_reloader=False)


if __name__ == '__main__':
    main()