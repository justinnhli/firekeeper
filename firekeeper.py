#!/usr/bin/env python3

# pylint: disable = missing-module-docstring, missing-class-docstring, missing-function-docstring

import re
import sqlite3
from argparse import ArgumentParser
from collections import defaultdict, Counter
from enum import Enum
from itertools import permutations, product, chain
from json import load as json_load, dumps as json_to_str
from pathlib import Path
from platform import system
from random import random, shuffle
from shutil import copyfile
from subprocess import run as run_subprocess
from tempfile import TemporaryDirectory
from time import sleep
from typing import Any, Optional
from urllib.parse import urlsplit


ARCHIVE_PATH = Path('~/media/web-archive').expanduser().resolve()


# CLASSES


class StatusTemp(Enum):
    # FIXME should use StrEnum from Python 3.11 instead
    # which allows for {'accepted': True}[Status.ACCEPTED]
    REJECTED = 'rejected'
    UNSORTED = 'unsorted'
    ACCEPTED = 'accepted'
    ARCHIVED = 'archived'


#REJECTED, UNSORTED, ACCEPTED, ARCHIVED = StatusTemp


class Status(str):
    pass


REJECTED = Status('rejected')
UNSORTED = Status('unsorted')
ACCEPTED = Status('accepted')
ARCHIVED = Status('archived')


class URL:

    def __init__(self, url):
        # type: (str) -> None
        parts = urlsplit(url.strip('/'))
        self.scheme, self.netloc, self.path, *_ = parts
        if parts.port:
            self.netloc = self.netloc[:-len(str(parts.port)) - 1]
        self.domain = '.'.join(self.netloc.split('.')[-2:])
        self.url = f'{self.scheme}://{self.netloc}{self.path}'

    def __eq__(self, other):
        # type: (Any) -> bool
        return self.url == other.url

    def __lt__(self, other):
        # type: (Any) -> bool
        return self.url < other.url

    def __hash__(self):
        # type: () -> int
        return hash(self.url)

    def __str__(self):
        # type: () -> str
        return str(self.url)

    @property
    def archive_path(self):
        # type: () -> Path
        return (
            ARCHIVE_PATH / f'{self.domain}/{self.netloc}{self.path}'
        ).with_suffix('.html')


class Rule:

    def __init__(self, rule_string):
        # type: (str) -> None
        self.rule_string = rule_string
        match = re.fullmatch(
            '(?P<preempt>!?)(?P<scheme>([a-z]*:)?)//(?P<netloc>[^/]*)/(?P<path>.*)',
            rule_string.strip(),
        )
        if not match:
            raise ValueError(f'rule does not contain the required pattern: {rule_string}')
        self.preempt = bool(match.group('preempt'))
        self.scheme_regex = re.compile(match.group('scheme').strip(':'), flags=re.IGNORECASE)
        self.netloc_regex = re.compile(f'{match.group("netloc")}$', flags=re.IGNORECASE)
        self.path_regex = re.compile(f'^{match.group("path")}', flags=re.IGNORECASE)

    def __eq__(self, other):
        # type: (Any) -> bool
        return self.rule_string == other.rule_string

    def __hash__(self):
        # type: () -> int
        return hash(self.rule_string)

    def __str__(self):
        # type: () -> str
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
        # type: () -> str
        return f'Rule("{self.rule_string}")'

    def matches(self, url):
        # type: (URL) -> bool
        return bool(
            self.scheme_regex.search(url.scheme)
            and self.netloc_regex.search(url.netloc)
            and self.path_regex.search(url.path.lstrip('/'))
        )


Cache = dict[Status, set[URL]]
RuleBook = dict[Status, list[Rule]]


def read_urls():
    # type: () -> Cache
    with open('urls', encoding='utf-8') as fd:
        return {
            status: set(URL(url) for url in urls)
            for status, urls in json_load(fd).items()
        }


def write_urls(cache):
    # type: (Cache) -> None
    json_obj = {
        status: sorted(str(url) for url in urls)
        for status, urls in cache.items()
    }
    with open('urls', 'w', encoding='utf-8') as fd:
        fd.write(json_to_str(json_obj, indent=4))


def read_rules():
    # type: () -> RuleBook
    with open('rules', encoding='utf-8') as fd:
        return {
            status: [Rule(rule) for rule in rules]
            for status, rules in json_load(fd).items()
        }


def write_rules(rules):
    # type: (RuleBook) -> None
    json_obj = {REJECTED: [], ACCEPTED: []} # type: dict[Status, list[str]]
    for status, ruleset in rules.items():
        json_obj[status] = sorted(str(rule) for rule in ruleset)
    with open('rules', 'w', encoding='utf-8') as fd:
        fd.write(json_to_str(json_obj, indent=4))


# MAIN


def main():
    # type: () -> None
    arg_parser = ArgumentParser()
    arg_parser.add_argument(
        'action',
        choices=['import', 'reset', 'status', 'archive', 'lint'],
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
        do_archive(cache, limit=5)
    elif args.action == 'lint':
        do_lint(cache)
    if args.action != 'status':
        do_status(cache)


# IMPORT


def do_import(cache):
    # type: (Cache) -> None
    add_history_to_cache(cache)
    write_urls(cache)
    process_urls(cache)
    write_urls(cache)


def add_history_to_cache(cache):
    # type: (Cache) -> None
    # pylint: disable = consider-using-f-string
    new_urls = get_history() - set().union(*cache.values())
    cache[UNSORTED].update(url for url in new_urls)


def get_history(profile=None):
    # type: (Optional[Path]) -> set[URL]
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
            urls.add(URL(row))
    return urls


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
    # type: (Path) -> Path
    db_path = profile / 'places.sqlite'
    assert db_path.exists()
    return db_path


def process_urls(cache, rules=None, from_status=UNSORTED):
    # type: (Cache, Optional[RuleBook], Status) -> None
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


def process_url(url, rules):
    # type: (URL, RuleBook) -> Status
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


# RESET


def do_reset(cache):
    # type: (Cache) -> None
    # reset the entire cache
    cache.clear()
    cache[REJECTED] = set()
    cache[UNSORTED] = set().union(
        cache[REJECTED],
        cache[UNSORTED],
        cache[ACCEPTED],
        cache[ARCHIVED],
    )
    cache[ACCEPTED] = set()
    cache[ARCHIVED] = set()
    # re-sort all urls
    process_urls(cache)
    # check for urls that have been archived
    used_archive_files = set()
    for url in list(cache[ACCEPTED]):
        archive_path = url.archive_path
        if archive_path.is_file():
            used_archive_files.add(archive_path)
            cache[ACCEPTED].discard(url)
            cache[ARCHIVED].add(url)
    # delete archived files that are not in the cache
    archive_files = set(ARCHIVE_PATH.glob('**/*.html'))
    for archive_file in archive_files - used_archive_files:
        archive_file.unlink()
        archive_dir = archive_file.parent
        while not any(archive_dir.iterdir()):
            archive_dir.rmdir()
            archive_dir = archive_dir.parent
    # update the cache file
    write_urls(cache)


# STATUS


def do_status(cache):
    # type: (Cache) -> None
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


# ARCHIVE


def do_archive(cache, limit=-1):
    # type: (Cache, int) -> None
    urls = list(cache[ACCEPTED])
    shuffle(urls)
    if limit > 0:
        urls = urls[:limit]
    for i, url in enumerate(urls, start=1):
        print(f'{i}/{limit}: {url}')
        archive_url(url)
        cache[ACCEPTED].discard(url)
        cache[ARCHIVED].add(url)
        sleep(1 + random())
    write_urls(cache)


def archive_url(url):
    # type: (URL) -> None
    archive_path = url.archive_path
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    command = [
        'monolith',
        #'--silent',
        '--no-js',
        '--isolate',
        '--insecure',
        '--timeout', '30',
        '--output', str(archive_path),
        str(url),
    ]
    run_subprocess(command, check=False)


# LINT


def do_lint(cache):
    # type: (Cache) -> None
    rules = read_rules()
    lint_conflicting_rules(cache, rules)
    lint_verify_archive(cache, rules)
    lint_redundant_rules(cache, rules)
    # FIXME list conflicting URLs


def lint_conflicting_rules(cache, rules):
    # type: (Cache, RuleBook) -> None
    for status, urls in cache.items():
        for url in urls:
            matches = {}
            for rule_type, ruleset in rules.items():
                matching_rules = [rule for rule in ruleset if rule.matches(url)]
                if matching_rules:
                    matches[rule_type] = matching_rules
            if len(matches) > 1:
                #print(f'URL matches multiple rulesets: {url}')
                pass
            if status != 'unsorted' and status not in matches:
                if status == REJECTED:
                    print(f'URL status does not correspond with matched rules: {url}')
                elif status in [ACCEPTED, ARCHIVED]:
                    print(f'URL status does not correspond with matched rules: {url}')


def lint_verify_archive(cache, _):
    # type: (Cache, RuleBook) -> None
    for url in cache[ARCHIVED]:
        if not url.archive_path.is_file():
            print(f'URL archive missing: {url}')


def lint_redundant_rules(cache, rulebook):
    # type: (Cache, RuleBook) -> None
    # pylint: disable = too-many-branches
    rules = [*rulebook[ACCEPTED], *rulebook[REJECTED]]
    for rule, count in Counter(rules).most_common():
        if count > 1:
            print(f'duplicate rule: {rule}')
        else:
            break
    dominating = defaultdict(set)
    for url in chain(*cache.values()):
        matched = set()
        unmatched = set()
        for rule in rules:
            if rule.matches(url):
                matched.add(rule)
            else:
                unmatched.add(rule)
        for matched_rule, unmatched_rule in product(matched, unmatched):
            dominating[matched_rule].add(unmatched_rule)
    unmatched_rules = set(rules) - set(dominating)
    for rule in unmatched_rules:
        print(f'rule never matched: {rule}')
    num_accepted = len(rulebook[ACCEPTED])
    for rule_subset in [rules[:num_accepted], rules[num_accepted:]]:
        for supord, subord in permutations(rule_subset, 2):
            if supord.preempt != subord.preempt:
                continue
            if subord in unmatched_rules:
                continue
            if subord in dominating[supord] and supord not in dominating[subord]:
                print(f'redundant rule: {supord} > {subord}')


if __name__ == '__main__':
    main()
