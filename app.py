"""Entry point: `python app.py` runs the development server."""
import os

from market import create_app, socketio

app = create_app()

if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    port = int(os.environ.get("PORT", "5000"))
    socketio.run(app, host="0.0.0.0", port=port, debug=debug,
                 allow_unsafe_werkzeug=True)
