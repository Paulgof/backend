from aiohttp import web
import aiohttp_jinja2
import jinja2
import asyncpg
from asyncpg.exceptions import DuplicateTableError
import re

FIELDS = {'entity_email', 'check-1', 'bio', 'superpowers', 'gender-group', 'entity_birth', 'entity_name', 'limbs'}

create_query = 'CREATE TABLE forms (' \
               'id bigint PRIMARY KEY GENERATED BY DEFAULT AS IDENTITY,' \
               'name VARCHAR(256),' \
               'email VARCHAR(256),' \
               'year INTEGER,' \
               'gender VARCHAR(256),' \
               'limbs VARCHAR(256),' \
               'superpowers TEXT[],' \
               'biography TEXT)'

insert_query = 'INSERT INTO forms (name, email, year, gender, limbs, superpowers, biography) VALUES (($1), ($2), ' \
               '($3), ($4), ($5), ($6), ($7))'


app = web.Application()
aiohttp_jinja2.setup(app, loader=jinja2.FileSystemLoader('./templates'))


async def create_table():
    con = await asyncpg.connect(user='kmx', database='back')
    try:
        await con.execute(create_query)
    except DuplicateTableError:
        print("Table forms already exists")
    await con.close()


async def insert(data):
    con = await asyncpg.connect(user='kmx', database='back')
    await con.execute(insert_query, data['entity_name'], data['entity_email'], int(data['entity_birth']),
                     data['gender-group'], data['limbs'], data.getall('superpowers'), data['bio'])
    await con.close()


@aiohttp_jinja2.template('index.jinja2')
async def index(request):
    return {'status': 200, 'errors': []}


@aiohttp_jinja2.template('index.jinja2', status=201)
async def form(request):
    data = await request.post()
    keys_set = {k for k in data}

    errors = []
    if len(FIELDS - keys_set) > 0:
        errors.append('empty fields')
        errors.extend(FIELDS - keys_set)
    elif len(keys_set - FIELDS) > 0:
        errors.append('too many fields')
    empties = list(filter(lambda x: data[x] is '', ('entity_name', 'entity_email', 'bio')))
    if len(empties) > 0:
        errors.append('empty fields')
        errors.extend(empties)
    else:
        if re.match(r'^[a-zA-Zа-яА-Я ]+$', data['entity_name']) is None:
            errors.extend(('incorrect field', 'entity_name'))
        if re.match(r'^[\w._]+@[a-z]+\.[a-z]+$', data['entity_email']) is None:
            errors.extend(('incorrect field', 'entity_email'))

    if len(errors) > 0:
        return {'status': 400, 'errors': errors}

    print(keys_set)
    for key in keys_set:
        print(data.getall(key))
    await insert(data)
    return {'status': 201, 'errors': []}


async def entrance():
    await create_table()
    app.add_routes([
        web.get('/task3', index),
        web.get('/task3/', index),
        web.post('/task3', form),
        web.post('/task3/', form)
    ])
    return app

if __name__ == '__main__':
    app.add_routes(routes)
    web.run_app(app)
