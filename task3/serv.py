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


def records_to_dict(recs):
    rec_dict = {'records': []}
    for r in recs:
        rec_dict['records'].append(dict())
        for key in r.keys():
            rec_dict['records'][-1][key] = r[key]
    return rec_dict


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


async def logout(request):
    session = await get_session(request)
    session['sid'] = None
    return web.HTTPSeeOther('/task3/set_form/0')


async def auth(request):
    success = True
    fall_response = web.HTTPSeeOther('/task3/login')
    success_response = web.HTTPSeeOther('/task3/set_form/0')
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
                success_response.set_cookie('user_generated', '1', max_age=5)
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
            if success:
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
        if data['login_name'] != "" and data['login_pass'] != ""\
                and all(re.match(r'^[a-zA-Z0-9_]+$', x) is not None for x in [data['login_name'], data['login_pass']]):
            password = await db.get_password(data['login_name'])
            if password is None:
                success = False
                fall_response.set_cookie('unknown_login', '1', max_age=5)
            elif md5(bytes(data['login_pass'], encoding='utf-8')).hexdigest() == password:
                sid = random_hash()
                await db.update_sid(data['login_name'], sid)
                session['sid'] = sid
            else:
                success = False
                fall_response.set_cookie('wrong_pass', '1', max_age=5)
        else:
            success = False
            fall_response.set_cookie('incor_login', '1', max_age=5)
            fall_response.set_cookie('incor_pass', '1', max_age=5)
    if success:
        return success_response
    return fall_response


async def index(request):
    session = await get_session(request)
    sid = session['sid'] if 'sid' in session else None
    sess_login = None
    recs = None

    if sid:
        sess_login = await db.get_login_by_sid(sid)
        uid = await db.get_uid_by_sid(sid)
        records = await db.get_forms_by_uid(uid)
        recs = records_to_dict(records)

    errors = request.cookies['errors'] if 'errors' in request.cookies else ""
    incor = request.cookies['incor_fields'] if 'incor_fields' in request.cookies else ""
    context = {
        'cookies': request.cookies,
        'errors': errors,
        'incor': incor,
        'is_auth': bool(sid),
        'sess_login': sess_login,
        'recs': recs
    }
    response = aiohttp_jinja2.render_template('index.jinja2', request, context)
    return response


async def form(request):
    data = await request.post()
    keys_set = {k for k in data}
    response = web.HTTPSeeOther('/task3/')
    session = await get_session(request)
    sid = session['sid'] if 'sid' in session else None
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
        if sid:
            uid = await db.get_uid_by_sid(sid)
        else:
            gen_login = await db.get_generated_user()
            gen_login = "user" + str(gen_login)
            password = random_hash()[:8]
            await db.insert_user(gen_login, md5(bytes(password, encoding='utf-8')).hexdigest())
            sid = random_hash()
            await db.update_sid(gen_login, sid)
            session['sid'] = sid
            response.set_cookie('user_generated', '1', max_age=5)
            response.set_cookie('login', gen_login, max_age=5)
            response.set_cookie('passwd', password, max_age=5)
            uid = await db.get_uid_by_sid(sid)
        if 'fid' in request.cookies:
            await db.update_form(int(request.cookies['fid']), data)
        else:
            await db.insert_form(data)
            fid = await db.get_last_fid()
            await db.insert_u2f(uid, fid)
        response.set_cookie('saved', 'True', max_age=1)
    return response


async def set_form(request):
    response = web.HTTPSeeOther('/task3/')
    rid = int(request.match_info['id'])
    if rid == 0:
        response.set_cookie('entity_name', '', max_age=0)
        response.set_cookie('entity_email', '', max_age=0)
        response.set_cookie('fid', '0', max_age=0)
    else:
        form_row = await db.get_form_by_id(rid)
        f_row = records_to_dict([form_row])['records'][0]
        response.set_cookie('entity_name', f_row['name'], max_age=YEAR)
        response.set_cookie('entity_email', f_row['email'], max_age=YEAR)
        response.set_cookie('fid', f_row['id'], max_age=YEAR)

    return response


async def entrance():
    await db.create_tables()
    app.add_routes([
        web.get('/task3', index),
        web.get('/task3/', index),
        web.post('/task3/', form),
        web.get('/task3/login', login),
        web.post('/task3/login', auth),
        web.get('/task3/logout', logout),
        web.get('/task3/set_form/{id}', set_form)
    ])
    setup(app, SimpleCookieStorage())
    return app

if __name__ == '__main__':
    web.run_app(entrance())
