#!/usr/bin/env python3

from firekeeper import REJECTED, UNSORTED, ACCEPTED, ARCHIVED
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
HARD_REJECTS = []


def create_rule_from_request(form):
    preempt = (form['preempt'] == 'true')
    if preempt:
        preempt_str = '!'
    else:
        preempt_str = ''
    scheme_pattern = form['scheme'].strip()
    netloc_pattern = form['netloc'].strip()
    path_pattern = form['path'].strip()
    return Rule(f'{preempt_str}{scheme_pattern}//{netloc_pattern}/{path_pattern}')


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
def home_view():
    return render_template('home.html')


@app.route('/rule')
def rule_view():
    return render_template('rule.html')


@app.route('/api/test-rule', methods=['POST'])
def test_rule():
    rule_type = request.json['rule_type']
    new_rule = create_rule_from_request(request.json)
    new_matched = []
    unmatched = []
    for url in URLS[UNSORTED]:
        if new_rule.matches(url):
            new_matched.append(url)
    if rule_type == ACCEPTED:
        if not HARD_REJECTS:
            preempt_rules = [rule for rule in RULES[REJECTED] if rule.preempt]
            for url in URLS[REJECTED]:
                if not any(rule.matches(url) for rule in preempt_rules):
                    HARD_REJECTS.append(url)
        for url in HARD_REJECTS:
            if new_rule.matches(url):
                unmatched.append(url)
    elif new_rule.preempt:
        for url in URLS[ACCEPTED]:
            if new_rule.matches(url):
                unmatched.append(url)
    for url in sorted(new_matched):
        print(url)
    result = jsonify({
        'rule_type': rule_type,
        'switched': urls_to_trie(unmatched),
        'matched': urls_to_trie(new_matched),
    })
    return result


@app.route('/api/add-rule', methods=['POST'])
def add_rule():
    accept_rule = (request.form['rule_type'] == 'accept')
    new_rule = create_rule_from_request(request.form)
    if accept_rule:
        new_rules = {ACCEPTED: [new_rule,],}
        RULES[ACCEPTED].append(new_rule)
    else:
        new_rules = {REJECTED: [new_rule,],}
        RULES[REJECTED].append(new_rule)
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
