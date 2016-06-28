import argparse
import hashlib
import os
import os.path
import requests
import time

from collections import namedtuple, OrderedDict
from functools import wraps
from inspect import getfullargspec
from urllib.parse import urljoin


BASE_URL = 'http://www.ex.ua/'

OK = '1'
ERROR = '0'
NOUSER = '0'

def _make_response(name, rettype):
    res = namedtuple(name, rettype)
    res.__nonzero__ = lambda self: int(self.code)
    return res

ErrorResponse = make_response('ErrorResponse', ('code', 'message'))

class ExError(Exception):
    pass


def apicall(fn):
    action = fn.__name__
    flag, name = action.split('_', 1)
    argspec = getfullargspec(fn)
    response = _make_response(name.capitalize() + 'Response',
                              argspec.annotations['return'])

    def _to_str(a):
        return str(a) if isinstance(a, int) else a

    @wraps(fn)
    def wrapper(self, *args):
        locals_ = fn(self, *args)
        params = OrderedDict([(arg, ('', _to_str(locals_[arg])))
                              for arg in argspec.args if arg != 'self'])

        if flag == 'i':
            url = urljoin(BASE_URL, action)
        elif flag == 'f' and self.authenticated:
            url = urljoin(self.fs_url, action)
        else:
            pass  # report not authenticated

        # NB: 'files' argument used because data should be sent as 
        # multipart/form-data, not application/x-www-form-urlencoded
        res = self._session.post(url, files=params)
        if res.status_code == requests.codes.ok:
            if '\n' in res.text:
                code, msg = res.text.splitlines()
                return ErrorResponse(code, msg)
            else:
                vals = res.text.split(',')
                return response(*vals)
        else:
            res.raise_for_status()
    return wrapper


def retry(fn, retries=100, time_sleep=1, *args, **kwargs):
    while retries > 0:
        res = fn(*args)
        if res:
            break
        else:
            retries -= 1
            time.sleep(time_sleep)
        
    return res


class Client:
    VERSION = 1

    def __init__(self):
        self.authenticated = False
        self._session = requests.Session()

    @apicall
    def i_version(self, version=VERSION) -> ('code', 'valid', 'server_version'):
        return locals()

    @apicall
    def i_login(self, login, password) -> ('code', 'uid', 'fs_id', 'max_size'):
        return locals()

    @apicall
    def i_access(self, login, password, object_id) -> ('code', 'oid', 'access', 'unknown'):
        return locals()

    @apicall
    def f_init(self, name, time, size) -> ('code', 'fid'):
        return locals()

    @apicall
    def f_write(self, fid, offset, length, content) -> ('code', 'size', 'md5'):
        return locals()

    @apicall
    def f_stat(self, fid) -> ('code', 'size', 'md5'):
        return locals()

    @apicall
    def f_done(self, fid, name, time, size, md5, login, password, object_id) -> ('code', 'upload_id', 'size', 'md5'):
        return locals()

    @apicall
    def f_remove(self, fid) -> 'code':
        return locals()


    ## Public API

    def connect(self, user, password):
        ver = self.i_version()
        if not ver or ver.valid != OK:
            raise False, 'Invalid protocol version'

        res = self.i_login(user, password)
        if not res or res.uid == NOUSER:
            return False, 'Login failed'

        self.user = user
        self.password = password
        self.uid = res.uid
        self.fs_id = res.fs_id
        self.max_size = int(res.max_size)
        self.fs_url = 'http://fs{}.www.ex.ua/'.format(self.fs_id)
        self.authenticated = True

        return True

    
    def upload(self, object_id, filename, block_size=1024*1024):
        if not self.authenticated:
            raise ExError('To upload files you should connect() first.')

        res = self.i_access(self.user, self.password, object_id)
        if not res or int(res.access) < 4:
            raise ExError('You do not have write access to object ' + object_id)

        stat = os.stat(filename)
        name = os.path.basename(filename)

        if stat.st_size > self.max_size:
            raise ExError('File size exceed max upload size')

        res = self.f_init(name, int(stat.st_mtime), stat.st_size)
        if not res:
            raise ExError('Failed to start upload, ' + res.message)

        fid = res.fid

        with open(filename, 'rb') as fo:
            ok, result = self._upload(fid, fo)
        
        if not ok:
            return False, result

        res = self.f_done(fid, name, int(stat.st_mtime), stat.st_size,
                          result, self.user, self.password, object_id)
    
        if res:
            return fid
        else:
            raise ExError('Upload to object {} failed. {}'.format(object_id, res.message))


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
                return False, 'MD5 calculation failed'
        
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
                        fo.seek(size)
                        offset = size
                        break

            # res = self.f_stat(fid)
            # if res:
            #     log('remote file size is {}, md5 is {}'.format(res.size, res.md5))
            # else:
            #     log ('failed to get upload information {}'.format(res.message))
            md5_local = md5_ctx.hexdigest()
            # print('local file md5 is {}'.format(md5_local))

            return True, md5_local


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='File uploader for http://www.ex.ua/.')
    parser.add_argument('-u', '--user', help='username', required=True)
    parser.add_argument('-p', '--password', help='password', required=True)
    parser.add_argument('-o', '--oid', help='remote object ID', required=True)
    parser.add_argument('files', help='files to upload', nargs=argparse.REMAINDER)
    args = parser.parse_args()

    if args.files:
        client = FileClient()
        client = FileClient.connect(args.user, args.password)
        for f in args.files:
            ok, result = client.upload(args.oid, f)
            if ok:
                print('{} successfully uploaded.'.format(f))
            else:
                print('Upload failed for {}. {}'.format(f, result))
