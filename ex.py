#!/usr/bin/env python

import argparse
import hashlib
import os
import os.path
import requests
import time

from collections import namedtuple, OrderedDict
from functools import wraps
from inspect import signature
from urllib.parse import urljoin


class ClientError(Exception):
    def __init__(self, message):
        self.message = message


class ServerError(Exception):
    def __init__(self, code, message):
        self.code = code
        self.message = message


def apicall(fn):
    action = fn.__name__
    flag, name = action.split('_', 1)
    sig = signature(fn)
    response = namedtuple(name.capitalize() + 'Response',
                          sig.return_annotation)
    response.__bool__ = lambda self: bool(self.code)
    base = {
        'i': lambda self: self.BASE_URL,
        'f': lambda self: self.fs_url,
    }[flag]

    @wraps(fn)
    def wrapper(self, *args):
        locals_ = fn(*args)
        params = OrderedDict(
            [(arg, ('', str(locals_[arg]))) for arg in sig.parameters])
        url = urljoin(base(self), action)

        if self.verbosity > 1:
            print('> {} -> {}'.format(action, locals_))
        # NB: 'files' argument used because data should be sent as
        # multipart/form-data, not application/x-www-form-urlencoded
        res = self._session.post(url, files=params)
        if self.verbosity > 1:
            print('< {} -> {}'.format(action, res.text))
        if res.status_code == requests.codes.ok:
            if '\n' in res.text:
                code, msg = res.text.splitlines()
                raise ServerError(int(code), msg)
            else:
                code, *vals = res.text.split(',')
                return response(int(code), *vals)
        else:
            res.raise_for_status()
    return wrapper


def retry(fn, retries=100, time_sleep=1, *args):
    while retries > 0:
        res = fn(*args)
        if res:
            break
        else:
            retries -= 1
            time.sleep(time_sleep)

    return res


class Client:
    """ Client for http://ex.ua """

    BASE_URL = 'http://www.ex.ua/'
    VERSION = 1

    def __init__(self, verbosity=0):
        self._session = requests.Session()
        self.verbosity = verbosity
        self.fs_url = None

    @apicall
    def i_version(version=VERSION) -> ('code', 'valid', 'server_version'):
        return locals()

    @apicall
    def i_login(login, password) -> ('code', 'uid', 'fs_id', 'max_size'):
        return locals()

    @apicall
    def i_access(login, password, object_id) -> ('code', 'oid', 'access', 'unknown1', 'unknown2'):
        return locals()

    @apicall
    def f_init(name, time, size) -> ('code', 'fid'):
        return locals()

    @apicall
    def f_write(fid, offset, length, content) -> ('code', 'size', 'md5'):
        return locals()

    @apicall
    def f_stat(fid) -> ('code', 'size', 'md5'):
        return locals()

    @apicall
    def f_done(fid, name, time, size, md5, login, password, object_id) -> ('code', 'upload_id', 'size', 'md5'):
        return locals()

    @apicall
    def f_remove(fid) -> ('code',):
        return locals()

    # PUBLIC

    def connect(self, user, password):
        OK = '1'
        NOUSER = '0'

        ver = self.i_version()
        if not ver or ver.valid != OK:
            raise ClientError('Invalid protocol version')

        res = self.i_login(user, password)
        if not res or res.uid == NOUSER:
            raise ClientError('Login failed')

        self.user = user
        self.password = password
        self.uid = int(res.uid)
        self.fs_id = int(res.fs_id)
        self.max_size = int(res.max_size)
        self.fs_url = 'http://fs{}.www.ex.ua/'.format(self.fs_id)

        return self.uid

    def upload(self, object_id, filename, block_size=1024*1024):
        if not self.fs_url:
            raise ClientError('To upload files you should connect() first')

        res = self.i_access(self.user, self.password, object_id)
        if not res or int(res.access) < 4:
            raise ClientError('You do not have write access to object ' + object_id)

        stat = os.stat(filename)
        name = os.path.basename(filename)

        if stat.st_size > self.max_size:
            raise ClientError('File size exceed max upload size')

        res = self.f_init(name, int(stat.st_mtime), stat.st_size)
        if not res:
            raise ClientError('Failed to start upload, ' + res.message)

        fid = res.fid

        with open(filename, 'rb') as fo:
            md5sum = self._upload(fid, fo)
            res = self.f_done(fid, name, int(stat.st_mtime), stat.st_size,
                              md5sum, self.user, self.password, object_id)
            if res:
                return fid
            else:
                raise ClientError('Upload to object {} failed. {}'.format(object_id, res.message))

    def _upload(self, fid, fo, bufsize=1024*1024):
        offset = 0
        length = 0
        buf = None

        md5_ctx = hashlib.md5()
        md5_offset = 0

        while True:
            buf = fo.read(bufsize)
            if not buf:
                break
            length = len(buf)
            if md5_offset == offset:
                md5_ctx.update(buf)
                md5_offset = offset + length
            elif md5_offset > offset and md5_offset < offset + length:
                md5_ctx.update(buf[md5_offset - offset:])
            else:
                raise ClientError('MD5 calculation failed')

            while True:
                res = self.f_write(fid, offset, length, buf)
                if res:
                    offset += length
                    break

                # log(' - block upload failed {}, retrying...'.format(res.message))
                res = retry(self.f_stat, fid)
                if res:
                    if res.size == offset + length:
                        break
                    elif res.size != offset:
                        fo.seek(res.size)
                        offset = res.size
                        break

            # res = self.f_stat(fid)
            # if res:
            #     log('remote file size is {}, md5 is {}'.format(res.size, res.md5))
            # else:
            #     log ('failed to get upload information {}'.format(res.message))
            md5_local = md5_ctx.hexdigest()
            # print('local file md5 is {}'.format(md5_local))

            return md5_local


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='File uploader for http://www.ex.ua/.')
    parser.add_argument('-u', '--user', help='username', required=True)
    parser.add_argument('-p', '--password', help='password', required=True)
    parser.add_argument('-o', '--oid', help='remote object ID', required=True)
    parser.add_argument('-v', '--verbose', help='enable verbose output',
                        action='count', default=0)
    parser.add_argument('files', help='files to upload', nargs=argparse.REMAINDER)
    args = parser.parse_args()

    if args.files:
        client = Client(verbosity=args.verbose)
        client.connect(args.user, args.password)
        for f in args.files:
            ok = client.upload(args.oid, f)
            msg = '{} successfully uploaded' if ok else 'Upload failed for {}'
            print(msg.format(f))
