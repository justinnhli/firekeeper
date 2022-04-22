#!/usr/bin/env python3

import re
import sqlite3
from argparse import ArgumentParser
from collections import namedtuple, defaultdict, Counter
from pathlib import Path
from platform import system
from subprocess import run
from urllib.parse import urlsplit, parse_qs, urlencode

import requests
from bs4 import BeautifulSoup

DOMNode = namedtuple('DOMNode', 'id, parent, tag, text')

if system() == 'Linux':
    DB_PATH = Path('~/.mozilla/firefox/1u9agml7.default-release')
    OPEN_PRG = 'xdg-open'
else:
    DB_PATH = Path('~/Library/Application Support/Firefox/Profiles/havj2vei.default-release')
    OPEN_PRG = 'open'
DB_PATH = DB_PATH.expanduser().resolve().joinpath('places.sqlite')


class TrieMap:

    def __init__(self):
        self.value = None
        self.terminal = False
        self.children = {}

    def __contains__(self, path):
        try:
            self[path]
        except KeyError:
            return False
        return True

    def __iter__(self):
        yield from self._iter([])

    def _iter(self, path):
        if self.terminal:
            yield path
        for value, child in sorted(self.children.items()):
            yield from child._iter(path + [value]) # pylint: disable = protected-access

    def _find_node(self, path, create=False):
        if len(path) == 0:
            return self
        if path[0] not in self.children:
            if not create:
                return None
            self.children[path[0]] = TrieMap()
        return self.children[path[0]]._find_node(path[1:], create=create) # pylint: disable = protected-access

    def __setitem__(self, path, value):
        node = self._find_node(path, create=True)
        node.terminal = True
        node.value = value

    def __getitem__(self, path):
        node = self._find_node(path)
        if node is None or not node.terminal:
            raise KeyError(path)
        return node.value

    def add(self, path):
        self[path] = None

    def setdefault(self, path, value):
        node = self._find_node(path, create=True)
        if not node.terminal:
            node.terminal = True
            node.value = value
        return node.value

    def get(self, path, default=None):
        node = self._find_node(path)
        if node.terminal:
            return node.value
        else:
            return default

    def items(self):
        yield from self._items([])

    def _items(self, path):
        if self.terminal:
            yield path, self.value
        for value, child in sorted(self.children.items()):
            yield from child._items(path + [value]) # pylint: disable = protected-access

    def has_prefix_of(self, path, min_length=1):
        if min_length <= 0:
            return True
        if len(path) == 0:
            return False
        if path[0] not in self.children:
            return False
        return self.children[path[0]].has_prefix_of(path[1:], min_length=min_length-1)

    def debug_print(self, depth=0):
        for value, child in sorted(self.children.items()):
            print(depth * '  ' + value)
            child.debug_print(depth + 1)


def export_history(path):
    con = sqlite3.connect(str(path))
    cur = con.cursor()
    return set(
        row[1] for row in cur.execute('SELECT * FROM moz_places')
    )


def read_cache(path):
    with path.open() as fd:
        return set(
            line.strip().replace('http://', 'https://') for line in fd.readlines()
            if not line.startswith('#')
        )


def read_query_list():
    allowed_parameters = defaultdict(set)
    with Path('query-list').open() as fd:
        for line in fd:
            parts = urlsplit(line.strip())
            if parts.query:
                parameters = parse_qs(parts.query)
                allowed_parameters[parts.netloc] |= parameters.keys()
    return allowed_parameters


class URL:

    QUERY_LIST = read_query_list()

    def __init__(self, url):
        if not re.match('[a-z]+://', url):
            url = 'https://' + url
        url = re.sub('^http:', 'https:', url)
        self.url = url
        self.valid = True
        if not self.url.startswith('http'):
            self.valid = False
        self.parts = urlsplit(self.url)
        if self.parts.hostname == 'localhost' or not re.search('[a-z]', self.parts.netloc):
            self.valid = False
        if self.valid:
            self.domain = '.'.join(self.parts.netloc.split('.')[-2:])
            self.url = f'{self.parts.scheme}://{self.parts.netloc}{self.parts.path}'
            query_str = urlencode({
                key: value
                for key, value in parse_qs(self.parts.query).items()
                if self.domain not in URL.QUERY_LIST or key in URL.QUERY_LIST[self.domain]
            })
            if self.parts.query and query_str:
                self.url += f'?{query_str}'
            self.parts = urlsplit(self.url)
        else:
            self.domain = None
        self.netloc_parts = tuple(reversed(self.parts.netloc.split('.')))
        self.path_parts = tuple(self.parts.path.split('/'))

    def __eq__(self, other):
        return self.url == other.url

    def __hash__(self):
        return hash(self.url)

    def __lt__(self, other):
        return (self.netloc_parts, self.path_parts) < (other.netloc_parts, other.path_parts) 

    def __str__(self):
        return self.url

    @property
    def netloc(self):
        return self.parts.netloc

    @property
    def hostname(self):
        return self.parts.hostname

    @property
    def path(self):
        return self.parts.path.strip('/')

    @property
    def query(self):
        return self.parts.query

    def endswith(self, suffix):
        return self.url.endswith(suffix)


class URLMatcher:

    def __init__(self, filepath):
        self.patterns = TrieMap()
        self._read_url_patterns(filepath)
        self.new_patterns = set()

    def _read_url_patterns(self, filepath):
        for url in read_cache(filepath):
            self.add_pattern(url, new=False)

    def matches(self, url):
        if url.netloc is None:
            return False
        netloc_parts = tuple(reversed(url.netloc.split('.')))
        path_parts = tuple(url.path.split('/'))
        if netloc_parts in self.patterns:
            return self.patterns[netloc_parts].has_prefix_of(path_parts, 0)
        else:
            return self.patterns.has_prefix_of(netloc_parts, 2)

    def add_pattern(self, pattern, new=True):
        if not re.match('[a-z]+://', pattern):
            pattern = 'https://' + pattern
        if not pattern.startswith('http'):
            return
        parts = urlsplit(pattern)
        if parts.netloc is None:
            return
        netloc_parts = tuple(reversed(parts.netloc.split('.')))
        path_parts = tuple(parts.path.strip('/').split('/'))
        self.patterns.setdefault(netloc_parts, TrieMap()).add(path_parts)
        if new:
            self.new_patterns.add(pattern)


INCLUDE_LIST = URLMatcher(Path('include-list'))
EXCLUDE_LIST = URLMatcher(Path('exclude-list'))


def read_urls():
    order = ['to-process', 'rejected', 'to-archive', 'archived']
    urls = {}
    with Path('urls').open() as fd:
        for line in fd:
            line = line.strip()
            if '\t' in line:
                url, status = line.split('\t')
            else:
                url = line
                status = 'to-process'
            url = URL(url)
            if url.valid:
                if url in urls:
                    status = max([status, urls[url]], key=order.index)
                urls[url] = status
    return urls


def print_help():
    print('y: yes (archive the URL)')
    print('n: no (do not archive the URL)')
    print('e: exclude (do not archive any URLs from this domain)')
    print('i: include (archive all URLs from this domain)')
    print('ee: exclude specific (exclude a URL pattern)')
    print('ii: include specific (include a URL pattern)')
    print('o: open (open the URL)')
    print('q: quit')
    print('h: help (print this message)')


def ask(url, urls, domains):
    # pylint: disable = no-else-continue
    while True:
        print()
        print(url)
        print(f'{domains[url.domain] - 1} other URLs from the same domain ({url.domain})')
        print()
        response = input('archive (y/N/e/i/o/q/h)? ').lower()
        if response == '':
            response = 'n'
        if response == 'o':
            run([OPEN_PRG, url], check=False)
        elif response == 'h':
            print_help()
        elif response in 'n':
            urls[url] = 'rejected'
        elif response == 'e':
            EXCLUDE_LIST.add_pattern(url.domain)
        elif response == 'ee':
            pattern = input('pattern to exclude: ') # TODO error checking?
            EXCLUDE_LIST.add_pattern(pattern)
        elif response == 'y':
            urls[url] = 'to-archive'
        elif response == 'i':
            INCLUDE_LIST.add_pattern(url.domain)
        elif response == 'ii':
            pattern = input('pattern to include: ') # TODO error checking?
            INCLUDE_LIST.add_pattern(pattern)
        elif response == 'q':
            raise KeyboardInterrupt()


BAD_FILETYPES = set(
    ['pdf', 'jpg', 'png', 'gif', 'gifv', 'jpeg', 'json']
)


def is_http_page(url):
    if url.domain is None or url.path == '':
        return False
    if Path(url.path).suffix.lower().strip('.') in BAD_FILETYPES:
        return False
    return True


def is_text_article(url):
    if url.endswith('.html'):
        return True
    response = requests.get(
        url,
        headers={
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:99.0) Gecko/20100101 Firefox/99.0',
        },
        verify=False,
    )
    if response.status_code != 200:
        return False
    soup = BeautifulSoup(response.text, 'html.parser')
    id_map = {}
    child_map = defaultdict(list)
    nodes = {}
    for node in soup.find_all():
        node_id = len(id_map)
        parent_id = id_map.get(node.parent, None)
        id_map[node] = node_id
        if node_id != parent_id:
            child_map[id_map.get(node.parent, None)].append(node_id)
        nodes[id_map[node]] = DOMNode(
            node_id,
            id_map.get(node.parent, None),
            node.name,
            ' '.join(node.stripped_strings),
        )
    root_size = len(nodes[0].text)
    for node_id, node in nodes.items():
        # must be 75% of the text of the page
        if len(node.text) < 0.75 * root_size:
            continue
        # TODO ideally, want to count something more sophisticated
        # eg. number of "paragraphs" with more than 3 sentences
        children = Counter(
            nodes[child_id].tag for child_id in child_map[node_id]
        )
        # must have 5 paragraphs
        if children['p'] < 5:
            continue
        # paragraphs must be the majority child tag
        if children['p'] < len(child_map[node_id]) / 2:
            continue
        return True
    return False


def process_urls(urls, interactive=True):
    skip_statuses = set(['rejected', 'to-archive', 'archived'])
    domains = Counter(url.domain for url in urls)
    queue = list(urls)
    while queue:
        url = queue.pop(0)
        if urls[url] in skip_statuses:
            continue
        if EXCLUDE_LIST.matches(url) or not is_http_page(url):
            urls[url] = 'rejected'
        elif INCLUDE_LIST.matches(url):
            if True or is_text_article(url): # FIXME
                urls[url] = 'to-archive'
        elif interactive:
            try:
                ask(url, urls, domains)
            except KeyboardInterrupt:
                break

def archive(urls):
    for url, status in urls.items():
        if status == 'to-archive':
            process = run(['save.sh', url], check=False)
            if process.returncode == 0:
                urls[url] = 'archived'


def main():
    urls = read_urls()
    statuses = Counter(status for url, status in urls.items())
    print('\n'.join(f'{status}: {count}' for status, count in statuses.most_common()))
    arg_parser = ArgumentParser()
    arg_parser.add_argument('action', choices=['batch', 'interactive', 'archive'], nargs='?', default='interactive')
    args = arg_parser.parse_args()
    if args.action == 'interactive':
        process_urls(urls)
    elif args.action == 'batch':
        process_urls(urls, interactive=False)
    elif args.action == 'archive':
        raise NotImplementedError()
        archive(urls)
    with Path('urls').open('w') as fd:
        for url, status in sorted(urls.items()):
            fd.write(f'{url}\t{status}')
            fd.write('\n')
    with Path('include-list').open('a') as fd:
        for pattern in sorted(INCLUDE_LIST.new_patterns):
            fd.write(pattern)
            fd.write('\n')
    with Path('exclude-list').open('a') as fd:
        for pattern in sorted(EXCLUDE_LIST.new_patterns):
            fd.write(pattern)
            fd.write('\n')


if __name__ == '__main__':
    main()
