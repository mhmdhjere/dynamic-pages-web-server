import asyncio
import sqlite3
import json
import aiofiles
import base64
import re
import config
import urllib.parse
from config import admin
from pathlib import Path
from aiohttp import web

PORT = config.port
TIMEOUT = config.timeout
POST_REQUEST = 1
DELETE_REQUEST = 0


async def non_dp_handle(path):
    extension = path.suffix[1:]
    async with aiofiles.open('mime.json', mode='r') as f:
        content1 = await f.read()
    data = json.loads(content1)
    async with aiofiles.open(path, mode="rb") as i:
        content2 = await i.read()

    content2 = content2.decode('utf-8')
    extension_map = {}
    for r in data['mime-mapping']:
        extension_map[r['extension']] = r['mime-type']
    try:
        content_type = extension_map[extension]
    except KeyError:
        content_type = 'text/plain'
        return web.Response(body=content2.encode('utf-8'), status=200,
                            headers={"Content-Type": content_type, "charset": "utf-8"})
    else:
        return web.Response(body=content2.encode('utf-8'), status=200,
                            headers={"Content-Type": content_type, "charset": "utf-8"})


# cmd is of form "{% python expression %}"
def command_reform(cmd):
    # remove '{%' and '%}'
    new_cmd = cmd[2:-2]
    # remove whitespaces from the beginning and the end
    new_cmd = new_cmd.strip()
    # handle newlines
    new_cmd = new_cmd.replace('\r\n', '\\\r\n')
    # ensure that no additional slashes were added
    new_cmd = new_cmd.replace('\\\\\r\n', '\\\r\n')
    return new_cmd


async def dp_handler(path, user, params):
    async with aiofiles.open(path, mode="rb") as i:
        content = await i.read()
    content = content.decode('utf-8')
    print(user)
    res = ''
    tokens = re.split(r"(?s)({%.*?%})", content)
    for token in tokens:
        translated = token
        if token.startswith('{%'):
            translated = eval(command_reform(token))
        res = res + translated
    return res


async def get_handler(request):
    print('GETTING...')
    path = Path(request.path[1:])
    extension = path.suffix
    # check file existence
    if not path.is_file():
        if path.name == 'favicon.ico':
            pass
        else:
            content = '404 Page not found'
            return web.Response(body=content.encode('utf-8'), status=404,
                                headers={"Content-Type": 'text/plain', "charset": "utf-8"})
    else:
        # ------------- dynamic pages handle -------------
        if extension == '.dp':
            # auth_user is the user requesting to get the .dp file
            # user is the dictionary needed in the context
            # params is the dictionary needed in the context
            user = {'username': None, 'authenticated': False}
            params = request.query
            auth_user = decode_auth(request)

            # check if the user exists in the database
            if auth_user:
                user = auth_user if user_in_db(auth_user) else user

            dp_content = await dp_handler(path, user, params)
            return web.Response(body=dp_content.encode('utf-8'), status=200,
                                headers={"Content-Type": 'text/html', "charset": "utf-8"})
        # ------------- non dynamic pages handle -------------
        # three cases:
        # 1. ends with extension which exists in mime.json        ---> mime-type (from the mime.json)
        # 2. ends with extension which doesn't exist in mime.json ---> plain/text
        # 3. no extension at all                                  ---> plain/text
        else:
            content = await non_dp_handle(path)
            return web.Response(body=content.encode('utf-8'), status=200,
                                headers={"Content-Type": 'text/html', "charset": "utf-8"})


def decode_auth(request):
    try:
        auth = request.headers['Authorization']
    except:
        return False
    else:
        cred_encoded = auth.split(' ')[1]
        cred_decoded = base64.b64decode(cred_encoded).decode('utf-8')
        credentials = cred_decoded.split(':')
        credentials = {'username': credentials[0], 'password': credentials[1]}
        return credentials


def authenticated(user):
    if not user:
        return False
    return (admin['username'] == user['username']) and (admin['password'] == user['password'])


async def decode_user(request):
    encoded_body = await request.content.read()
    tmp = urllib.parse.parse_qs(encoded_body.decode('utf-8'))
    new_user = {'username': tmp['username'][0], 'password': tmp['password'][0]}
    return new_user


def user_in_db(user):
    db = sqlite3.connect('users.db')
    cur = db.cursor()
    cur.execute("SELECT * FROM Users WHERE username=? AND password=?", (user['username'], user['password']))
    rows = cur.fetchall()
    db.close()
    return True if rows else False


def add_user_to_db(new_user):
    db = sqlite3.connect('users.db')
    db.execute('INSERT into USERS VALUES (?,?)', [new_user['username'], new_user['password']])
    db.commit()
    db.close()


def delete_user_from_db(username):
    db = sqlite3.connect('users.db')
    db.execute('DELETE FROM USERS WHERE username=?', [username])
    db.commit()
    db.close()


# request_type:
# 1/POST_REQUEST if the request is POST
# 0/DELETE_REQUEST if the request is DELETE
def valid_users_path(path, request_type):
    path_dirs = path.parts
    match request_type:
        case 1:
            return path_dirs[1] == 'users' and len(path_dirs) == 2
        case 0:
            return path_dirs[1] == 'users' and len(path_dirs) == 3
        case _:
            return False


async def post_handler(request):
    print('POSTING...')
    path = Path(request.path)
    user = decode_auth(request)
    new_user = await decode_user(request)
    # ensure path is \users - otherwise return error
    if not valid_users_path(path, POST_REQUEST):
        content = 'Bad request'
        return web.Response(body=content.encode('utf-8'), status=400,
                            headers={"Content-Type": 'text/plain', "charset": "utf-8"})
    # ensure this is the admin -  otherwise return unauthorized
    if not authenticated(user):
        content = 'Unauthorized user'
        return web.Response(body=content.encode('utf-8'), status=401,
                            headers={"Content-Type": 'text/plain', "charset": "utf-8"})

    # ensure user doesn't exist in the database - otherwise return error
    if user_in_db(new_user):
        content = 'Error: user already exists'
        return web.Response(body=content.encode('utf-8'), status=403,
                            headers={"Content-Type": 'text/plain', "charset": "utf-8"})

    add_user_to_db(new_user)
    name = new_user['username']
    content = f'User {name} was added successfully to the database'
    return web.Response(body=content.encode('utf-8'), status=200,
                        headers={"Content-Type": 'text/plain', "charset": "utf-8"})


async def delete_handler(request):
    print('DELETING...')
    path = Path(request.path)
    user = decode_auth(request)
    user_to_delete = path.name
    # ensure path is \users\<username> - otherwise return error
    if not valid_users_path(path, DELETE_REQUEST):
        content = 'Bad request'
        return web.Response(body=content.encode('utf-8'), status=400,
                            headers={"Content-Type": 'text/plain', "charset": "utf-8"})
    # ensure this is the admin -  otherwise return unauthorized
    if not authenticated(user):
        content = 'Unauthorized user'
        return web.Response(body=content.encode('utf-8'), status=401,
                            headers={"Content-Type": 'text/plain', "charset": "utf-8"})

    # delete user from database - doesn't matter if he already exists
    delete_user_from_db(user_to_delete)
    content = f'User {user_to_delete} was deleted successfully from the database'
    return web.Response(body=content.encode('utf-8'), status=200,
                        headers={"Content-Type": 'text/plain', "charset": "utf-8"})


handlers = {'GET': get_handler, 'POST': post_handler, 'DELETE': delete_handler}


async def handler(request):
    try:
        return await handlers[request.method](request)
    except KeyError:

        content = request.method + ' is not implemented.'
        return web.Response(body=content.encode('utf-8'), status=501,
                            headers={"Content-Type": 'text/plain', "charset": "utf-8"})


async def main():
    server = web.Server(handler)
    runner = web.ServerRunner(server)
    await runner.setup()
    site = web.TCPSite(runner, 'localhost', PORT)
    await site.start()

    print("======= Serving on http://127.0.0.1:8001/ ======")


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    future = asyncio.ensure_future(main())
    loop.run_forever()
