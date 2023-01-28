#!/usr/bin/env python3

import re
import sqlite3
from time import sleep
from random import random, shuffle
from argparse import ArgumentParser
from enum import Enum
from json import load as json_load, dump as json_dump
from pathlib import Path
from platform import system
from shutil import copyfile
from subprocess import run as run_subprocess
from tempfile import TemporaryDirectory
from urllib.parse import urlsplit

ARCHIVE_PATH = Path('~/media/web-archive').expanduser().resolve()


class Status(Enum):
    # FIXME should use StrEnum from Python 3.11 instead
    # which allows for {'accepted': True}[Status.ACCEPTED]
    REJECTED = 'rejected'
    UNSORTED = 'unsorted'
    ACCEPTED = 'accepted'
    ARCHIVED = 'archived'


REJECTED, UNSORTED, ACCEPTED, ARCHIVED = Status
REJECTED = 'rejected'
UNSORTED = 'unsorted'
ACCEPTED = 'accepted'
ARCHIVED = 'archived'


def get_profile():
    # type: () -> Path
    if system() == 'Linux':
        profiles_path = Path('~/.mozilla/firefox')
    else:
        profiles_path = Path('~/Library/Application Support/Firefox/Profiles')
    return max(
        (
            child for child in profiles_path.expanduser().resolve().iterdir()
            if child.is_dir() and '.' in child.name
        ),
        key=(lambda path: path.stat().st_mtime),
    )


def get_places_db(profile):
    db_path = profile / 'places.sqlite'
    assert db_path.exists()
    return db_path


def get_history(profile=None):
    if profile is None:
        profile = get_profile()
    db_path = get_places_db(profile)
    # make a copy of the database to avoid locks
    urls = set()
    with TemporaryDirectory() as temp_dir:
        temp_db = Path(temp_dir) / 'temp.sqlite'
        copyfile(db_path, temp_db)
        con = sqlite3.connect(temp_db)
        cur = con.cursor()
        for row, in cur.execute('SELECT DISTINCT url FROM moz_places'):
            urls.add(row)
    return urls


class URL:

    def __init__(self, url):
        self.url = url
        _, self.netloc, self.path, *_ = urlsplit(url)
        self.domain = '.'.join(self.netloc.split('.')[-2:])

    def __str__(self):
        return self.url

    def __hash__(self):
        return hash(self.url)

class URLSet:

    class Node:

        def __init__(self, end=False):
            self.end = end
            self.children = {}

        def __getitem__(self, key):
            return self.children[key]

        def __setitem__(self, key, value):
            self.children[key] = value

        def __contains__(self, part):
            return part in self.children

    def __init__(self, urls):
        self.root = URLSet.Node()
        for url in urls:
            self.add(url)

    def add(self, url):
        node = self.root
        for part in url.parts:
            if part not in node:
                node[part] = URLSet.Node()
            node = node[part]
        node.end = True


    def discard(self, url):
        pass # FIXME


def read_urls():
    with open('urls', encoding='utf-8') as fd:
        return {status: set(urls) for status, urls in json_load(fd).items()}


def write_urls(cache):
    cache_obj = {status: sorted(urls) for status, urls in cache.items()}
    with open('urls', 'w', encoding='utf-8') as fd:
        json_dump(cache_obj, fd)


class Rule:

    def __init__(self, rule_string):
        self.rule_string = rule_string
        match = re.fullmatch('(?P<preempt>!?)(?P<scheme>([a-z]*:)?)//(?P<netloc>[^/]*)/(?P<path>.*)', rule_string.strip())
        if not match:
            raise ValueError(f'rule does not contain the required pattern: {rule_string}')
        self.preempt = bool(match.group('preempt'))
        self.scheme_regex = re.compile(match.group('scheme').strip(':'), flags=re.IGNORECASE)
        self.netloc_regex = re.compile(f'{match.group("netloc")}$', flags=re.IGNORECASE)
        self.path_regex = re.compile(f'^{match.group("path")}', flags=re.IGNORECASE)

    def __str__(self):
        if self.preempt:
            preempt_pattern = '!'
        else:
            preempt_pattern = ''
        scheme_pattern = self.scheme_regex.pattern
        if scheme_pattern:
            scheme_pattern += ':'
        netloc_pattern = self.netloc_regex.pattern
        if netloc_pattern:
            netloc_pattern = netloc_pattern.rstrip('$')
        path_pattern = self.path_regex.pattern
        if path_pattern:
            path_pattern = path_pattern.lstrip('^')
        result = f'{preempt_pattern}{scheme_pattern}//{netloc_pattern}/{path_pattern}'
        assert self.rule_string == result, f'"{self.rule_string}" != {result}'
        return result

    def __repr__(self):
        return f'Rule("{self.rule_string}")'

    def matches(self, url):
        parts = urlsplit(url)
        scheme, netloc, path, *_ = parts
        if parts.port:
            netloc = netloc[:-len(str(parts.port)) - 1]
        return (
            self.scheme_regex.search(scheme)
            and self.netloc_regex.search(netloc)
            and self.path_regex.search(path.lstrip('/'))
        )


def read_rules():
    with open('rules', encoding='utf-8') as fd:
        return {
            status: [Rule(rule) for rule in rules]
            for status, rules in json_load(fd).items()
        }


def write_rules(rules):
    rules_obj = {REJECTED: [], ACCEPTED: []}
    for status, ruleset in rules.items():
        rules_obj[status] = sorted(str(rule) for rule in ruleset)
    with open('rules', 'w', encoding='utf-8') as fd:
        json_dump(rules_obj, fd)


def add_history_to_cache(cache):
    history = get_history()
    new_urls = history - set().union(*cache.values())
    cache[UNSORTED].update(new_urls)


def process_url(url, rules):
    rejected = False
    for rule in rules.get(REJECTED, []):
        if rule.matches(url):
            if rule.preempt:
                return REJECTED
            rejected = True
    for rule in rules.get(ACCEPTED, []):
        if rule.matches(url):
            return ACCEPTED
    if rejected:
        return REJECTED
    else:
        return UNSORTED


def process_urls(cache, rules=None, from_status=UNSORTED):
    if rules is None:
        rules = read_rules()
    for url in list(cache[from_status]):
        status = process_url(url, rules)
        if status == ACCEPTED:
            cache[from_status].discard(url)
            cache[ACCEPTED].add(url)
        elif status == REJECTED:
            cache[from_status].discard(url)
            cache[REJECTED].add(url)


def get_archive_path(url):
    parts = urlsplit(url)
    _, netloc, path, *_ = parts
    domain = '.'.join(netloc.split('.')[-2:])
    result = ARCHIVE_PATH / f'{domain}/{netloc}{path}'
    if result.suffix != '.html':
        result = result.parent / (result.stem + '.html')
    return result


def archive_url(url):
    archive_path = get_archive_path(url)
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    command = [
        'monolith',
        #'--silent',
        '--no-js',
        '--isolate',
        '--insecure',
        '--timeout', '30',
        '--output', str(archive_path),
        url,
    ]
    print(' '.join(command))
    run_subprocess(command, check=True)


def lint_conflicting_rules(cache, rules):
    for status, urls in cache.items():
        for url in urls:
            matches = {}
            for rule_type, ruleset in rules.items():
                matching_rules = [rule for rule in ruleset if rule.matches(url)]
                if matching_rules:
                    matches[rule_type] = matching_rules
            if status not in matches or len(matches) > 1:
                print(f'URL status does not correspond with matched rules: {url}')


def lint_verify_archive(cache, _):
    for url in cache[ARCHIVED]:
        path = get_archive_path(url)
        if not path.exists():
            print(f'URL archive missing: {url}')


def lint(cache):
    rules = read_rules()
    lint_conflicting_rules(cache, rules)
    lint_verify_archive(cache, rules)


def do_status(cache):
    rejected = len(cache[REJECTED])
    unsorted = len(cache[UNSORTED])
    accepted = len(cache[ACCEPTED])
    archived = len(cache[ARCHIVED])
    total = rejected + unsorted + accepted + archived
    print(' '.join([
        f'{rejected:,d} ({rejected / total:.2%}) <-',
        f'{unsorted:,d} ({unsorted / total:.2%}) ->',
        f'{accepted:,d} ({accepted / total:.2%}) ->',
        f'{archived:,d} ({archived / total:.2%})',
    ]))


def do_reset(cache):
    # reset the entire cache
    cache = {
        REJECTED: set(),
        UNSORTED: set().union(
            cache[REJECTED],
            cache[UNSORTED],
            cache[ACCEPTED],
            cache[ARCHIVED],
        ),
        ACCEPTED: set(),
        ARCHIVED: set(),
    }
    # re-sort all urls
    process_urls(cache)
    # check for urls that have been archived
    used_archive_files = set()
    for url in list(cache[ACCEPTED]):
        path = get_archive_path(url)
        if path.exists():
            used_archive_files.add(path)
            cache[ACCEPTED].discard(url)
            cache[ARCHIVED].add(url)
    # delete archived files that are not in the cache
    archive_files = set(ARCHIVE_PATH.glob('**/*.html'))
    for archive_file in archive_files - used_archive_files:
        archive_file.unlink()
        # FIXME deal with now-empty directories
    # update the cache file
    write_urls(cache)


def do_import(cache):
    add_history_to_cache(cache)
    write_urls(cache)
    process_urls(cache)
    write_urls(cache)


def do_archive(cache, limit=10):
    urls = list(cache[ACCEPTED])
    #urls = [url for url in urls if 'washingtonpost' in url]
    shuffle(urls)
    if limit:
        urls = urls[:limit]
    for url in urls:
        archive_url(url)
        sleep(1 + random())
        cache[ACCEPTED].discard(url)
        cache[ARCHIVED].add(url)


def do_lint(cache):
    # check for redundant rules
    # list conflicting URLs
    pass


def main():
    arg_parser = ArgumentParser()
    arg_parser.add_argument(
        'action',
        choices=['status', 'reset', 'import', 'archive', 'lint'],
        default='status',
        nargs='?',
    )
    args = arg_parser.parse_args()
    cache = read_urls()
    do_status(cache)
    if args.action == 'reset':
        do_reset(cache)
    elif args.action == 'import':
        do_import(cache)
    elif args.action == 'archive':
        do_archive(cache)
    elif args.action == 'lint':
        do_lint(cache)
    if args.action != 'status':
        do_status(cache)


if __name__ == '__main__':
    main()
