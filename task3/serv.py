from aiohttp_session import setup, get_session
from aiohttp_session import SimpleCookieStorage
from aiohttp import web
from hashlib import md5
import aiohttp_jinja2
import jinja2
import time
import re
import db

FIELDS = {'entity_email', 'check', 'bio', 'superpowers', 'gender-group', 'entity_birth', 'entity_name', 'limbs'}

YEAR = 365 * 24 * 60 * 60


app = web.Application()
aiohttp_jinja2.setup(app, loader=jinja2.FileSystemLoader('./templates'))


def random_hash():
    return md5(bytes(str(time.time()), encoding='utf-8')).hexdigest()


async def login(request):
    session = await get_session(request)
    sid = session['sid'] if 'sid' in session else None
    # if sid is not None:
    #     return web.HTTPSeeOther('/task3/')
    context = {
        'has_auth': sid is not None,
        'incor_login': 'incor_login' in request.cookies,
        'incor_pass': 'incor_pass' in request.cookies,
        'wrong_pass': 'wrong_pass' in request.cookies,
        'login_taken': 'login_taken' in request.cookies,
        'unknown_login': 'unknown_login' in request.cookies
    }
    response = aiohttp_jinja2.render_template('login.jinja2', request, context)
    return response


async def auth(request):
    success = True
    fall_response = web.HTTPSeeOther('/task3/login')
    success_response = web.HTTPSeeOther('/task3/')
    data = await request.post()
    session = await get_session(request)
    if data['sign_type'] == 'Sign Up':
        if data['login_name'] == "" or data['login_pass'] == "":
            gen_login = await db.get_generated_user()
            gen_login = "user" + str(gen_login)
            password = random_hash()[:8]
            try:
                await db.insert_user(gen_login, md5(bytes(password, encoding='utf-8')).hexdigest())
                sid = random_hash()
                await db.update_sid(gen_login, sid)
                session['sid'] = sid
                success_response.set_cookie('login', gen_login, max_age=5)
                success_response.set_cookie('passwd', password, max_age=5)
            except KeyError:
                success = False
                fall_response.set_cookie('login_taken', '1', max_age=5)

        else:
            if re.match(r'^[a-zA-Z0-9_]+$', data['login_name']) is None:
                success = False
                fall_response.set_cookie('incor_login', '1', max_age=5)
            if re.match(r'^[a-zA-Z0-9_]+$', data['login_name']) is None:
                success = False
                fall_response.set_cookie('incor_pass', '1', max_age=5)
            try:
                await db.insert_user(data['login_name'],
                                     md5(bytes(data['login_pass'], encoding='utf-8')).hexdigest())
                sid = random_hash()
                await db.update_sid(data['login_name'], sid)
                session['sid'] = sid
            except KeyError:
                success = False
                fall_response.set_cookie('login_taken', '1', max_age=5)
    else:
        if data['login_name'] != "" and data['login_pass'] != "":
            password = await db.get_password(data['login_name'])
            if password is None:
                success = False
                fall_response.set_cookie('unknown_login', '1', max_age=5)
            if md5(bytes(data['login_pass'], encoding='utf-8')).hexdigest() == password:
                sid = random_hash()
                await db.update_sid(data['login_name'], sid)
                session['sid'] = sid
            else:
                success = False
                fall_response.set_cookie('wrong_pass', '1', max_age=5)
        else:
            success = False
    if success:
        return success_response
    return fall_response


async def index(request):
    print(request.cookies)
    session = await get_session(request)
    print(session)
    # last_visit = session['last_visit'] if 'last_visit' in session else None
    # session['last_visit'] = time.time()
    # print('Last visited: {}'.format(last_visit))
    sid = session['sid'] if 'sid' in session else None
    # if sid is None:
    #     return web.HTTPSeeOther('/task3/login')
    errors = request.cookies['errors'] if 'errors' in request.cookies else ""
    incor = request.cookies['incor_fields'] if 'incor_fields' in request.cookies else ""
    context = {'cookies': request.cookies, 'errors': errors, 'incor': incor}
    response = aiohttp_jinja2.render_template('index.jinja2', request, context)
    return response


async def form(request):
    data = await request.post()
    keys_set = {k for k in data}
    response = web.HTTPSeeOther('/task3/')
    errors = []
    incorrect_fields = []
    if len(FIELDS - keys_set) > 0:
        errors.extend(FIELDS - keys_set)
    elif len(keys_set - FIELDS) > 0:
        errors.append('too many fields')
    empties = list(filter(lambda x: data[x] is '', ('entity_name', 'entity_email', 'bio')))

    if len(empties) > 0:
        errors.extend(empties)

    if re.match(r'^[a-zA-Zа-яА-Я ]+$', data['entity_name']) is None and 'entity_name' not in empties:
        errors.append('entity_name')
        incorrect_fields.append('entity_name')
    if re.match(r'^[\w._]+@[a-z]+\.[a-z]+$', data['entity_email']) is None and 'entity_email' not in empties:
        errors.append('entity_email')
        incorrect_fields.append('entity_email')

    response.set_cookie('errors', str(errors), max_age=1)
    response.set_cookie('incor_fields', str(incorrect_fields), max_age=1)

    response.set_cookie('entity_name', data['entity_name'], max_age=YEAR)
    response.set_cookie('entity_email', data['entity_email'], max_age=YEAR)

    if len(errors) > 0:
        response.set_cookie('saved', 'False', max_age=1)
    else:
        await db.insert_form(data)
        response.set_cookie('saved', 'True', max_age=YEAR)
    return response


async def entrance():
    await db.create_tables()
    app.add_routes([
        web.get('/task3', index),
        web.get('/task3/', index),
        web.post('/task3/', form),
        web.get('/task3/login', login),
        web.post('/task3/login', auth)
    ])
    setup(app, SimpleCookieStorage())
    return app

if __name__ == '__main__':
    web.run_app(entrance())
