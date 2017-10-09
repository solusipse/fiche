from flask import Flask, abort, redirect
app = Flask(__name__)

import argparse, os, pygments
from pygments import highlight
from pygments.lexers import guess_lexer
from pygments.formatters import HtmlFormatter

parser = argparse.ArgumentParser()
parser.add_argument("root_dir", help="Path to directory with pastes")
args = parser.parse_args()


@app.route('/')
def main():
    return redirect("http://termbin.com", code=302)


@app.route('/<slug>')
def beautify(slug):
    # Return 404 in case of urls longer than 64 chars
    if len(slug) > 64:
        abort(404)

    # Create path for the target dir
    target_dir = os.path.join(args.root_dir, slug)

    # Block directory traversal attempts
    if not target_dir.startswith(args.root_dir):
        abort(404)

    # Check if directory with requested slug exists
    if os.path.isdir(target_dir):
        target_file = os.path.join(target_dir, "index.txt")
        
        # File index.txt found inside that dir
        with open(target_file) as f:
            code = f.read()
            # Identify language
            lexer = guess_lexer(code)
            # Create formatter with line numbers
            formatter = HtmlFormatter(linenos=True, full=True)
            # Return parsed code
            return highlight(code, lexer, formatter)

    # Not found
    abort(404)


if __name__ == '__main__':
    app.run()
