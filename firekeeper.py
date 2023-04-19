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
from typing import Any, Optional, Iterable
from urllib.parse import urlsplit


ARCHIVE_PATH = Path('~/media/web-archive').expanduser().resolve()
URLS_FILE = Path('~/Dropbox/personal/logs/urls').expanduser().resolve()
RULES_FILE = Path(__file__).parent / 'rules'
URLS_LOCK_FILE = URLS_FILE.with_suffix('.lock')


# CLASSES


class StatusTemp(Enum):
    # FIXME should use StrEnum from Python 3.11 instead
    # which allows for {'accepted': True}[Status.ACCEPTED]
    EXPUNGED = 'expunged'
    REJECTED = 'rejected'
    UNSORTED = 'unsorted'
    ACCEPTED = 'accepted'
    ARCHIVED = 'archived'


#REJECTED, UNSORTED, ACCEPTED, ARCHIVED = StatusTemp


class Status(str):
    pass


EXPUNGED = Status('expunged')
REJECTED = Status('rejected')
UNSORTED = Status('unsorted')
ACCEPTED = Status('accepted')
ARCHIVED = Status('archived')


class URL:

    def __init__(self, url):
        # type: (str) -> None
        parts = urlsplit(url)
        self.scheme, self.netloc, self.path, *_ = parts
        if parts.port:
            self.netloc = self.netloc[:-len(str(parts.port)) - 1]
        subdomains = self.netloc.split('.')
        if subdomains[-1] in ('uk', 'au'):
            self.domain = '.'.join(subdomains[-3:])
        else:
            self.domain = '.'.join(subdomains[-2:])
        self.path = self.path.rstrip('/')
        self.url = f'https://{self.netloc}{self.path}'

    def __eq__(self, other):
        # type: (Any) -> bool
        return self.url == other.url

    def __lt__(self, other):
        # type: (Any) -> bool
        return self.sort_key < other.sort_key

    def __hash__(self):
        # type: () -> int
        return hash(self.url)

    def __str__(self):
        # type: () -> str
        return str(self.url)

    @property
    def sort_key(self):
        # type: () -> tuple[str, str, str]
        return (self.domain, self.netloc, self.path)

    @property
    def archive_path(self):
        # type: () -> Path
        return (
            ARCHIVE_PATH / f'{self.domain}/{self.netloc}{self.path}'
        ).with_suffix('.html')

    @property
    def valid(self):
        # type: () -> bool
        return bool(
            self.scheme.startswith('http')
            and self.netloc
        )


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

    def __lt__(self, other):
        # type: (Any) -> bool
        return self.sort_key < other.sort_key

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

    @property
    def sort_key(self):
        # type: () -> tuple[bool, str, str]
        return (
            not self.preempt,
            self.netloc_regex.pattern,
            self.path_regex.pattern,
        )

    def matches(self, url):
        # type: (URL) -> bool
        return bool(
            self.scheme_regex.search(url.scheme)
            and self.netloc_regex.search(url.netloc)
            and self.path_regex.search(url.path.lstrip('/'))
        )


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
        urls.update(
            URL(row) for row, in (
                sqlite3.connect(temp_db).cursor()
                .execute('SELECT DISTINCT url FROM moz_places')
            )
        )
    return urls


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
    # check if the download failed (eg. if the URL does not exist)
    if not archive_path.exists():
        return False
    # delete if not HTML
    process = run_subprocess(['file', str(archive_path)], check=True, capture_output=True)
    if 'text' not in process.stdout.decode('utf-8'):
        return False
    # reduce file size
    try:
        with archive_path.open() as fd:
            html = fd.read()
    except UnicodeDecodeError:
        return True
    html = re.sub('<script.*?</script>', '', html, flags=re.DOTALL)
    html = re.sub('"data:[^"]*"', '""', html)
    html = re.sub(r'^\s*', '', html, flags=re.MULTILINE)
    html = re.sub(r'\s*$', '', html, flags=re.MULTILINE)
    html = re.sub('\n+', '\n', html)
    with archive_path.open('w') as fd:
        fd.write(html)


class FireKeeper:

    def __init__(self, urls_path, rules_path, archive_path):
        # type: (Path, Path, Path) -> None
        # constants
        self.urls_path = urls_path
        self.rules_path = rules_path
        self.archive_path = archive_path
        self.lock_path = self.urls_path.with_suffix('.lock')
        # variables
        self.urls = {} # type: dict[Status, set[URL]]
        self.rules = {} # type: dict[Status, list[Rule]]
        self._init_urls()
        self._read_urls()
        self._read_rules()

    def _init_urls(self):
        # type: () -> None
        self.urls = {
            REJECTED: set(),
            UNSORTED: set(),
            ACCEPTED: set(),
            ARCHIVED: set(),
        }

    def _read_urls(self):
        # type: () -> None
        with self.urls_path.open(encoding='utf-8') as fd:
            self.urls = {
                status: set(URL(url) for url in urls)
                for status, urls in json_load(fd).items()
            }

    def write_urls(self, path=None):
        # type: (Optional[Path]) -> None
        if path is None:
            path = self.urls_path
        json_obj = {
            status: [str(url) for url in sorted(urls)]
            for status, urls in self.urls.items()
        }
        with path.open('w', encoding='utf-8') as fd:
            fd.write(json_to_str(json_obj, indent=4))
            fd.write('\n')

    def _read_rules(self):
        # type: () -> None
        with self.rules_path.open(encoding='utf-8') as fd:
            self.rules = {
                status: [Rule(rule) for rule in rules]
                for status, rules in json_load(fd).items()
            }
        self.rules[REJECTED].extend(self.rules[EXPUNGED])

    def write_rules(self, path=None):
        # type: (Optional[Path]) -> None
        if path is None:
            path = self.rules_path
        json_obj = {
            EXPUNGED: [],
            REJECTED: [],
            ACCEPTED: [],
        } # type: dict[Status, list[str]]
        expunged = set(self.rules[EXPUNGED])
        for status, ruleset in self.rules.items():
            if status == REJECTED:
                ruleset = [rule for rule in ruleset if rule not in expunged]
            json_obj[status] = [str(rule) for rule in sorted(ruleset)]
        with path.open('w', encoding='utf-8') as fd:
            fd.write(json_to_str(json_obj, indent=4))
            fd.write('\n')

    def _lock(self):
        # type: () -> None
        if self.lock_path.exists():
            raise RuntimeError(f'lock file exists: {self.lock_path}')
        self.lock_path.touch()

    def _unlock(self):
        # type: () -> None
        self.lock_path.unlink(missing_ok=True)

    def _process_urls(self, from_status=UNSORTED):
        # type: (Status) -> None
        for url in list(self.urls[from_status]):
            status = self.classify_url(url)
            if status == ACCEPTED:
                self.urls[from_status].discard(url)
                self.urls[ACCEPTED].add(url)
            elif status == REJECTED:
                self.urls[from_status].discard(url)
                self.urls[REJECTED].add(url)


    def add(self, urls):
        # type: (Iterable[URL]) -> None
        self._lock()
        old_urls = set().union(*self.urls.values())
        self.urls[UNSORTED].update(
            url for url in urls
            if (
                url.valid
                and url not in old_urls
                and not any(rule.matches(url) for rule in self.rules[EXPUNGED])
            )
        )
        self._process_urls()
        self.write_urls()
        self._unlock()

    def import_from_firefox(self):
        # type: () -> None
        self.add(get_history())

    def classify_url(self, url):
        # type: (URL) -> Status
        rejected = False
        for rule in self.rules.get(REJECTED, []):
            if rule.matches(url):
                if rule.preempt:
                    return REJECTED
                rejected = True
        for rule in self.rules.get(ACCEPTED, []):
            if rule.matches(url):
                return ACCEPTED
        if rejected:
            return REJECTED
        else:
            return UNSORTED

    def archive(self, limit=-1):
        # type: (int) -> None
        self._lock()
        urls = list(self.urls[ACCEPTED])
        shuffle(urls)
        if limit > 0:
            urls = urls[:limit]
        else:
            limit = len(urls)
        for i, url in enumerate(urls, start=1):
            print(f'{i}/{limit}: {url}')
            if archive_url(url):
                self.urls[ACCEPTED].discard(url)
                self.urls[ARCHIVED].add(url)
            else:
                pass # FIXME need to decide how database should be updated
            sleep(1 + random())
        self.write_urls()
        self._unlock()

    def status(self):
        # type: () -> None
        rejected = len(self.urls[REJECTED])
        unsorted = len(self.urls[UNSORTED])
        accepted = len(self.urls[ACCEPTED])
        archived = len(self.urls[ARCHIVED])
        total = rejected + unsorted + accepted + archived
        print(' '.join([
            f'{rejected:,d} ({rejected / total:.2%}) <-',
            f'{unsorted:,d} ({unsorted / total:.2%}) ->',
            f'{accepted:,d} ({accepted / total:.2%}) ->',
            f'{archived:,d} ({archived / total:.2%})',
        ]))

    def reset(self): # FIXME should rename this function
        # type: () -> None
        # re-sort all urls
        urls = set().union(*self.urls.values())
        self._init_urls()
        self.add(urls)
        # check for urls that have been archived
        self._lock()
        used_archive_files = set()
        for url in list(self.urls[ACCEPTED]):
            archive_path = url.archive_path
            if archive_path.is_file():
                used_archive_files.add(archive_path)
                self.urls[ACCEPTED].discard(url)
                self.urls[ARCHIVED].add(url)
        self.write_urls()
        self._unlock()
        # delete archived files that are not in the cache
        archive_files = set(ARCHIVE_PATH.glob('**/*.html'))
        for archive_file in archive_files - used_archive_files:
            archive_file.unlink()
            archive_dir = archive_file.parent
            while not any(archive_dir.iterdir()):
                archive_dir.rmdir()
                archive_dir = archive_dir.parent

    def lint(self):
        # type: () -> None
        self.lint_verify_archive()
        self.lint_redundant_rules()

    def lint_verify_archive(self):
        # type: () -> None
        for url in self.urls[ARCHIVED]:
            if not url.archive_path.is_file():
                print(f'URL archive missing: {url}')

    def lint_redundant_rules(self):
        # type: () -> None
        # pylint: disable = too-many-branches
        rules = [*self.rules[ACCEPTED], *self.rules[REJECTED]]
        for rule, count in Counter(rules).most_common():
            if count > 1:
                print(f'duplicate rule: {rule}')
            else:
                break
        dominating = defaultdict(set)
        for url in chain(*self.urls.values()):
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
        num_accepted = len(self.rules[ACCEPTED])
        for rule_subset in [rules[:num_accepted], rules[num_accepted:]]:
            for supord, subord in permutations(rule_subset, 2):
                if supord.preempt != subord.preempt:
                    continue
                if subord in unmatched_rules:
                    continue
                if subord in dominating[supord] and supord not in dominating[subord]:
                    print(f'redundant rule: {supord} > {subord}')


# MAIN


def workspace(firekeeper):
    # type: (FireKeeper) -> None
    # pylint: disable = unused-argument
    pass


def main():
    # type: () -> None
    archive_actions = set(['reset', 'archive', 'lint'])
    modifying_actions = set(['reset', 'import', 'archive'])
    arg_parser = ArgumentParser()
    arg_parser.add_argument(
        'action',
        choices=['import', 'reset', 'status', 'archive', 'lint', 'workspace'],
        default='status',
        nargs='?',
        help='action to perform (default: %(default)s)',
    )
    args = arg_parser.parse_args()
    if args.action in archive_actions and not ARCHIVE_PATH.exists():
        raise FileNotFoundError(ARCHIVE_PATH)
    if args.action in modifying_actions:
        if URLS_LOCK_FILE.exists():
            raise RuntimeError(f'lock file exists: {URLS_LOCK_FILE}')
    firekeeper = FireKeeper(URLS_FILE, RULES_FILE, ARCHIVE_PATH)
    firekeeper.status()
    if args.action == 'reset':
        firekeeper.reset()
    elif args.action == 'import':
        firekeeper.import_from_firefox()
    elif args.action == 'archive':
        firekeeper.archive()
    elif args.action == 'lint':
        firekeeper.lint()
    elif args.action == 'workspace':
        workspace(firekeeper)
    if args.action != 'status':
        firekeeper.status()


if __name__ == '__main__':
    main()
