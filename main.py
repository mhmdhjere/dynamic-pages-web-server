import asyncio
import sqlite3
import json
import aiofiles
import base64
import re
import config
import urllib.parse
from pathlib import Path
from aiohttp import web
from datetime import datetime
from time import mktime
from wsgiref.handlers import format_date_time

PORT = config.port


############################### ERROR HANDLING ###############################
#                                                                            #
#   200 (OK) - returned where everything is ok:                              #
#       GET - requested file is read successfully                            #
#       POST - the user was added successfully by the admin                  #
#       DELETE - the user was deleted successfully by the admin              #
#                                                                            #
#   400 (Bad Request) - the request has invalid form, still a legal one:     #
#       POST - the path is not /users or the body is not of correct form     #
#       DELETE - the path is not of form users/<username>                    #
#                                                                            #
#   401 (Unauthorized) - unauthorized access to some resource:               #
#       POST - non-Basic authorization                                       #
#       DELETE - non-Basic authorization                                     #
#                                                                            #
#   403 (Forbidden) - unauthorized user request:                             #
#       POST - the user is not an admin with correct credentials             #
#       DELETE - the user is not an admin with correct credentials           #
#                                                                            #
#   404 (Not Found) - returned when the requested file is missing:           #
#       GET - the requested file is not found                                #
#                                                                            #
#   409 (Conflict) - a conflict in the existing data with the new one:       #
#       POST - the user to be added is already in the database               #
#                                                                            #
#   500 (Internal Server Error) - an error that happens due to failure of    #
#   finishing the request (database error, reading files error, etc..)       #
#                                                                            #
#   501 (Not Implemented) - the request type is not supported in the server  #
#                                                                            #
##############################################################################


# gives the correct date-time format for HTTP requests
def date_http():
    now = datetime.now()
    now_tuple = now.timetuple()
    now_timestamp = mktime(now_tuple)
    date = format_date_time(now_timestamp)
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

    if extension in extension_map:
        content_type = extension_map[extension]
    else:
        content_type = 'text/plain'
    content_len = f"{len(content)}"
    return content, content_type


# cmd is of form "{% python expression %}"
def command_reform(cmd):
    # remove '{%' and '%}'
    new_cmd = cmd[2:-2]
    # remove whitespaces from the beginning and the end
    new_cmd = new_cmd.strip()
    return new_cmd


# parses the dynamic page
async def dp_parser(path, user, params):
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


# decodes the user from the Authorization header
def decode_auth(request):
    if 'Authorization' not in request.headers:
        return False
    else:
        auth = request.headers['Authorization']
        cred_encoded_list = auth.split(' ')
        cred_encoded = cred_encoded_list[1]
        cred_decoded = base64.b64decode(cred_encoded).decode('utf-8')
        credentials = cred_decoded.split(':')
        credentials = {'username': credentials[0], 'password': credentials[1]}
        return credentials


def authenticated(user):
    if not user:
        return False
    return (config.admin['username'] == user['username']) and (config.admin['password'] == user['password'])


# decodes the user from the x-www-form-urlencoded body (used in POST requests)
async def decode_user(request):
    encoded_body = await request.read()
    cred_dict = urllib.parse.parse_qs(encoded_body.decode('utf-8'))
    username = cred_dict['username'][0]
    password = cred_dict['password'][0]
    new_user = {'username': username, 'password': password}
    return new_user


def user_in_db(username):
    with sqlite3.connect('users.db') as db:
        cur = db.cursor()
        cur.execute("SELECT * FROM Users WHERE username=?", (username,))
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


# check if the request has the right form
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


# check if the authorization method is Basic
def is_basic_auth(request):
    if 'Authorization' not in request.headers:
        return False
    return 'Basic' in request.headers['Authorization']


async def dp_handle(request):
    # auth_user is the user requesting to get the .dp file
    # user is the dictionary needed in the context
    # params is the dictionary needed in the context
    user = {'username': None, 'authenticated': False}
    path = Path(request.path[1:])
    params = request.query
    auth_user = decode_auth(request)
    # check if the user exists in the database
    if auth_user:
        user = auth_user if user_in_db(auth_user) else user
    content = await dp_parser(path, user, params)
    return content, 'text/html'


async def get_handler(request):
    print('GETTING...')
    path = Path(request.path[1:])
    extension = path.suffix
    content_type = 'text/plain'
    status = 200
    # path.parts splits the path and return its parts (in this case without the root (aka /))
    is_root_path = True if not path.parts else False
    # check if the requested path is the root path
    if is_root_path or path.name == 'favicon.ico':
        content = 'Welcome Bro!'
    # check file existence
    elif path.is_file():
        # ------------- dynamic pages handle -------------
        if extension == '.dp':
            content, content_type = await dp_handle(request)
        # ------------- non dynamic pages handle -------------
        # three cases:
        # 1. ends with extension which exists in mime.json        ---> mime-type (from the mime.json)
        # 2. ends with extension which doesn't exist in mime.json ---> plain/text
        # 3. no extension at all                                  ---> plain/text
        else:
            content, content_type = await non_dp_handle(path)
    else:
        content = '404 Page not found.'
        status = 404

    return content, content_type, status


async def post_handler(request):
    print('POSTING...')
    user = decode_auth(request)
    status = 200
    # ensure path is \users and the body is of the right format- otherwise return 400 (Bad Request)
    if not await valid_request(request):
        content = 'Bad request.'
        status = 400
    # ensure the authorization is Basic -  otherwise return unauthorized
    elif not is_basic_auth(request):
        content = 'Unauthorized request.'
        status = 401
    # ensure this is the admin - otherwise return forbidden
    elif not authenticated(user):
        content = 'Forbidden.'
        status = 403
    # ensure user doesn't exist in the database - otherwise return Conflict
    else:
        new_user = await decode_user(request)
        name = new_user['username']
        if user_in_db(name):
            content = f'Conflict error: user {name} already exists.'
            status = 409
        else:
            add_user_to_db(new_user)
            content = f'User {name} was added successfully to the database.'
    return content, 'text/plain', status


async def delete_handler(request):
    print('DELETING...')
    path = Path(request.path)
    user = decode_auth(request)
    user_to_delete = path.name
    status = 200
    # ensure path is \users\<username> and format- otherwise return 400 (Bad Request)
    if not await valid_request(request):
        content = 'Bad request.'
        status = 400
    # ensure the authorization is Basic -  otherwise return unauthorized
    elif not is_basic_auth(request):
        content = 'Unauthorized request.'
        status = 401
    # ensure this is the admin - otherwise return forbidden
    elif not authenticated(user):
        content = 'Forbidden.'
        status = 403
    # delete user from database - doesn't matter if he already exists
    else:
        delete_user_from_db(user_to_delete)
        content = f'User {user_to_delete} was deleted successfully from the database.'

    return content, 'text/plain', status


handlers = {'GET': get_handler, 'POST': post_handler, 'DELETE': delete_handler}


async def handler(request):
    try:
        if request.method in handlers:
            content, content_type, status = await handlers[request.method](request)
        else:
            content = request.method + ' is not implemented.'
            content_type = 'text/plain'
            status = 501
    except:
        content = 'Some internal server error has occurred.'
        content_type = 'text/plain'
        status = 500
    content_len = f"{len(content)}"
    return web.Response(body=content.encode('utf-8'), status=status,
                        headers={"Connection": 'close', "Content-Type": content_type, "charset": "utf-8", "Date": date_http(),
                                 "Content-Length": content_len})


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
