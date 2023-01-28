#!/usr/bin/env python3

from urllib.parse import urlsplit

from firekeeper import Status, REJECTED, UNSORTED, ACCEPTED, ARCHIVED
from firekeeper import Rule, read_urls, read_rules, write_urls, write_rules, process_urls

try:
    from flask import Flask, render_template, request, jsonify
except (ModuleNotFoundError, ImportError) as err:

    def run_with_venv(venv):
        # type: (str) -> None
        """Run this script in a virtual environment.

        Parameters:
            venv (str): The virtual environment to use.

        Raises:
            FileNotFoundError: If the virtual environment does not exist.
            ImportError: If the virtual environment does not contain the necessary packages.
        """
        # pylint: disable = ungrouped-imports, reimported, redefined-outer-name, import-outside-toplevel
        import sys
        from os import environ, execv
        from pathlib import Path
        venv_python = Path(environ['PYTHON_VENV_HOME'], venv, 'bin', 'python3').expanduser()
        if not venv_python.exists():
            raise FileNotFoundError(f'could not find venv "{venv}" at executable {venv_python}')
        if sys.executable == str(venv_python):
            raise ImportError(f'no module {err.name} in venv "{venv}" ({venv_python})')
        execv(str(venv_python), [str(venv_python), *sys.argv])

    run_with_venv('flask-heroku')


app = Flask(__name__)


RULES = read_rules()
URLS = read_urls()


def urls_to_trie(urls):

    def recursive_sort(nodes):
        return sorted(
            (
                {
                    'part': part,
                    'count': count,
                    'children': recursive_sort(children),
                } for part, (count, children) in nodes.items()
            ),
            key=(lambda obj: (-obj['count'], obj['part'])),
        )

    trie = {}
    for url in urls:
        parts = [url.domain, url.netloc, *url.path.strip('/').split('/')]
        parent = trie
        for part in parts:
            if part not in parent:
                parent[part] = [0, {}]
            parent[part][0] += 1
            parent = parent[part][1]
    return recursive_sort(trie)


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/api/add-rule', methods=['POST'])
def add_rule():
    accept_rule = (request.form['rule_type'] == 'accept')
    preempt = (request.form['preempt'] == 'true')
    if preempt:
        preempt_str = '!'
    else:
        preempt_str = ''
    scheme_pattern = request.form['scheme'].strip()
    netloc_pattern = request.form['netloc'].strip()
    path_pattern = request.form['path'].strip()
    rule = Rule(f'{preempt_str}{scheme_pattern}//{netloc_pattern}/{path_pattern}')
    if accept_rule:
        new_rules = {ACCEPTED: [rule,],}
        RULES[ACCEPTED].append(rule)
    else:
        new_rules = {REJECTED: [rule,],}
        RULES[REJECTED].append(rule)
    write_rules(RULES)
    '''
    process_urls(URLS)
    if accept_rule:
        process_urls(URLS, rules=new_rules, from_status=REJECTED)
    else:
        process_urls(URLS, rules=new_rules, from_status=ACCEPTED)
    write_urls(URLS)
    '''
    return jsonify(success=True)


@app.route('/api/get-urls/<status>')
def get_urls(status):
    if status == 'rejected':
        urls = sorted(URLS[REJECTED])
    elif status == 'unsorted':
        urls = sorted(URLS[UNSORTED])
    elif status == 'accepted':
        urls = sorted(URLS[ACCEPTED] | URLS[ARCHIVED])
    elif status == 'conflict':
        urls = [] # FIXME

    return jsonify({
        'status': status,
        'count': len(urls),
        'trie': urls_to_trie(urls),
    })


if __name__ == '__main__':
    app.run(debug=True)
