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
from datetime import datetime
from time import mktime
from wsgiref.handlers import format_date_time

PORT = config.port
TIMEOUT = config.timeout
POST_REQUEST = 1
DELETE_REQUEST = 0

#TODO connection close add to headers


############################### ERROR HANDLING ###############################
#                                                                            #
#   200 (OK) - returned where everything is ok:                              #
#       GET - requested file is read successfully                            #
#       POST - the user was added successfully by the admin                  #
#       DELETE - the user was deleted successfully by the admin              #
#                                                                            #
#   400 (Bad Request) - the request has invalid form, still a legal one:     #
#       POST - the path is not /users                                        #
#       DELETE - the path is not of form users/<username>                    #
#                                                                            #
#   401 (Unauthorized) - unauthorized access to some resource:               #
#       GET - non-Basic authorization on dynamic page request                #
#       POST - wrong admin password or non-Basic authorization               #
#       DELETE - wrong admin password or non-Basic authorization             #
#                                                                            #
#   403 (Forbidden) - unauthorized user request:                             #
#       POST - the user is not an admin                                      #
#       DELETE - the user is not an admin                                    #
#                                                                            #
#   404 (Not Found) - returned when the requested file is missing:           #
#       GET - the requested file is not found                                #
#                                                                            #
#   409 (Conflict) - a conflict in the existing data with the new one:       #
#       POST - the user to be added is already in the database               #
#                                                                            #
#   500 (Internal Server Error) - an error that happens due to failure of    #
#   finishing the request                                                    #
#                                                                            #
#   501 (Not Implemented) - the request type is not supported in the server  #
#                                                                            #
##############################################################################


def date_http():
    now = datetime.now()
    nowtuple = now.timetuple()
    nowtimestamp = mktime(nowtuple)
    date = format_date_time(nowtimestamp)
    return date


async def non_dp_handle(path):
    extension = path.suffix[1:]
    async with aiofiles.open('mime.json', mode='r') as f:
        content1 = await f.read()
    data = json.loads(content1)
    async with aiofiles.open(path, mode="rb") as i:
        content = await i.read()
    content = content.decode('utf-8')
    extension_map = {}
    for r in data['mime-mapping']:
        extension_map[r['extension']] = r['mime-type']
    try:
        content_type = extension_map[extension]
    except KeyError:
        content_type = 'text/plain'
        content_len = f"{len(content)}"
        return web.Response(body=content.encode('utf-8'), status=200,
                            headers={"Content-Type": content_type, "charset": "utf-8", "Date": date_http(), "Content"
                                                                                                            "-Length": content_len})
    else:
        content_len = f"{len(content)}"
        return web.Response(body=content.encode('utf-8'), status=200,
                            headers={"Content-Type": content_type, "charset": "utf-8", "Date": date_http(), "Content-Length": content_len})


# cmd is of form "{% python expression %}"
def command_reform(cmd):
    # remove '{%' and '%}'
    new_cmd = cmd[2:-2]
    # remove whitespaces from the beginning and the end
    new_cmd = new_cmd.strip()
    return new_cmd


async def dp_handler(path, user, params):
    async with aiofiles.open(path, mode="rb") as i:
        content = await i.read()
    content = content.decode('utf-8')
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
    # path.parts splits the path and return its parts (in this case without the root (aka /))
    is_root_path = True if not path.parts else False
    # check if the requested path is the root path
    if is_root_path:
        content = 'Welcome Bro!'
        content_len = f"{len(content)}"
        return web.Response(body=content.encode('utf-8'), status=200,
                            headers={"Content-Type": 'text/html', "charset": "utf-8", "Date": date_http(), "Content-Length": content_len})
    # check file existence
    elif path.is_file():
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
            content_len = f"{len(dp_content)}"
            return web.Response(body=dp_content.encode('utf-8'), status=200,
                                headers={"Content-Type": 'text/html', "charset": "utf-8", "Date": date_http(), "Content-Length": content_len})
        # ------------- non dynamic pages handle -------------
        # three cases:
        # 1. ends with extension which exists in mime.json        ---> mime-type (from the mime.json)
        # 2. ends with extension which doesn't exist in mime.json ---> plain/text
        # 3. no extension at all                                  ---> plain/text
        else:
            content = await non_dp_handle(path)
            return content
        ###################
    else:
        if path.name == 'favicon.ico':
            pass
        else:
            content = '404 Page not found'
            content_len = f"{len(content)}"
            return web.Response(body=content.encode('utf-8'), status=404,
                                headers={"Content-Type": 'text/plain', "charset": "utf-8", "Date": date_http(), "Content-Length": content_len})


def decode_auth(request):
    try:
        auth = request.headers['Authorization']
    except KeyError:
        return False
    else:
        cred_encoded_list = auth.split(' ')
        cred_encoded = cred_encoded_list[1]
        cred_decoded = base64.b64decode(cred_encoded).decode('utf-8')
        credentials = cred_decoded.split(':')
        credentials = {'username': credentials[0], 'password': credentials[1]}
        return credentials


def authenticated(user):
    if not user:
        return False
    return (admin['username'] == user['username']) and (admin['password'] == user['password'])


async def decode_user(request):
    encoded_body = await request.read()
    cred_dict = urllib.parse.parse_qs(encoded_body.decode('utf-8'))
    username = cred_dict['username'][0]
    password = cred_dict['password'][0]
    new_user = {'username': username, 'password': password}
    return new_user


def user_in_db(user):
    with sqlite3.connect('users.db') as db:
        cur = db.cursor()
        cur.execute("SELECT * FROM Users WHERE username=? AND password=?", (user['username'], user['password']))
        rows = cur.fetchall()
    return True if rows else False


def add_user_to_db(new_user):
    with sqlite3.connect('users.db') as db:
        db.execute('INSERT into USERS VALUES (?,?)', [new_user['username'], new_user['password']])
        db.commit()


def delete_user_from_db(username):
    with sqlite3.connect('users.db') as db:
        db.execute('DELETE FROM Users WHERE username=?', [username])
        db.commit()


# request_type:
# 1/POST_REQUEST if the request is POST
# 0/DELETE_REQUEST if the request is DELETE
async def valid_request(request):
    path = Path(request.path)
    path_dirs = path.parts
    request_type = request.method
    valid_path = True
    try:
        if request_type == 'POST':

            valid_path = path_dirs[1] == 'users' and len(path_dirs) == 2
            user = await decode_user(request)
        elif request_type == 'DELETE':
            valid_path = path_dirs[1] == 'users' and len(path_dirs) == 3
    except (IndexError, KeyError):
        return False
    else:
        return valid_path


async def post_handler(request):
    print('POSTING...')
    user = decode_auth(request)
    status = 200
    # ensure path is \users and the body is of the right format- otherwise return 400 (Bad Request)
    if not await valid_request(request):
        content = 'Bad request'
        status = 400
    # ensure the authorization is Basic -  otherwise return unauthorized
    elif not is_basic_auth(request):
        content = 'Unauthorized request'
        status = 401
    # ensure this is the admin - otherwise return forbidden
    elif not authenticated(user):
        content = 'Forbidden'
        status = 403
    # ensure user doesn't exist in the database - otherwise return Conflict
    else:
        new_user = await decode_user(request)
        name = new_user['username']
        if user_in_db(new_user):
            content = f'Conflict error: user {name} already exists'
            status = 409
        else:
            add_user_to_db(new_user)
            content = f'User {name} was added successfully to the database'
    content_len = f"{len(content)}"
    return web.Response(body=content.encode('utf-8'), status=status,
                        headers={"Content-Type": 'text/plain', "charset": "utf-8", "Date": date_http(), "Content-Length": content_len})


# check if the authorization method is Basic
def is_basic_auth(request):
    if 'Authorization' not in request.headers:
        return False
    return 'Basic' in request.headers['Authorization']


async def delete_handler(request):
    print('DELETING...')
    path = Path(request.path)
    user = decode_auth(request)
    user_to_delete = path.name
    status = 200
    # ensure path is \users and the body is of the right format- otherwise return 400 (Bad Request)
    if not await valid_request(request):
        content = 'Bad request'
        status = 400
    # ensure the authorization is Basic -  otherwise return unauthorized
    elif not is_basic_auth(request):
        content = 'Unauthorized request'
        status = 401
    # ensure this is the admin - otherwise return forbidden
    elif not authenticated(user):
        content = 'Forbidden'
        status = 403
    # delete user from database - doesn't matter if he already exists
    else:
        delete_user_from_db(user_to_delete)
        content = f'User {user_to_delete} was deleted successfully from the database'
    content_len = f"{len(content)}"
    return web.Response(body=content.encode('utf-8'), status=status,
                        headers={"Content-Type": 'text/plain', "charset": "utf-8", "Date": date_http(), "Content-Length": content_len})


handlers = {'GET': get_handler, 'POST': post_handler, 'DELETE': delete_handler}


async def handler(request):
    try:
        return await handlers[request.method](request)
    except KeyError:
        content = request.method + ' is not implemented.'
        content_len = f"{len(content)}"
        return web.Response(body=content.encode('utf-8'), status=501,
                            headers={"Content-Type": 'text/plain', "charset": "utf-8", "Date": date_http(), "Content-Length": content_len})
    except:
        content = 'Some internal server error has occurred.'
        content_len = f"{len(content)}"
        return web.Response(body=content.encode('utf-8'), status=500,
                            headers={"Content-Type": 'text/plain', "charset": "utf-8", "Date": date_http(), "Content-Length": content_len})


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
