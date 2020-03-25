from aiohttp import web
import aiohttp_jinja2
import jinja2

app = web.Application()
routes = web.RouteTableDef()
aiohttp_jinja2.setup(app, loader=jinja2.FileSystemLoader('./templates'))


@routes.get('/task3')
@aiohttp_jinja2.template('index.jinja2')
async def index(request):
    return {'status': 200, 'errors': []}


@routes.post('/task3')
@aiohttp_jinja2.template('index.jinja2', status=201)
async def form(request):
    data = await request.post()
    print(data)
    return {'status': 201, 'errors': []}


if __name__ == '__main__':
    app.add_routes(routes)
    web.run_app(app)
