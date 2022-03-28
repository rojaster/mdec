import tempfile
import traceback
import argparse

from aiohttp import web
import aiohttp




# TODO(alekum): This part should be splitted as Service must provide what is required
# to handle requests/responses.
# 1. Identify Models
# 2. Identify Controllers
# 3. Idnetify Services
class Service:
    """
    Decompiler/Lifter as a service
    """

    def __init__(self):
        self.app = web.Application()
        self.app.add_routes([web.post('/lifting', self.post_lifting)])
        self.app.add_routes([web.post('/decompile', self.post_decompile)])
        self.app.add_routes([web.get('/version', self.get_version)])

    def decompile(self, path: str) -> str:
        # raise NotImplementedError("Required to be implemented in subclass")
        return f"Required to be implemented in subclass {self.__class__.__name__}"

    def version(self) -> str:
        # raise NotImplementedError("Required to be implemented in subclass")
        return f"Required to be implemented in subclass {self.__class__.__name__}"

    def lifting(self, path: str) -> str:
        # raise NotImplementedError("Required to be implemented in subclass")
        return f"Required to be implemented in subclass {self.__class__.__name__}"

    async def handler(self, action_method, request: aiohttp.web.BaseRequest) -> web.Response:
        """ Processing handler, common interface 
        Process user request and handle action accordingly.
        Currently it should be refactored as Service should transfer responsibility to process
        action to the controler and focus on web requests only.
        """
        reader = await request.multipart()
        binary = await reader.next()
        if binary is None:
            return web.Response(status=400)

        with tempfile.NamedTemporaryFile() as f:
            while True:
                chunk = await binary.read_chunk()
                if not chunk:
                    break
                f.write(chunk)
                f.flush()

            try:
                body = action_method(f.name)
                resp_status = 200
            except:
                body = traceback.format_exc()
                resp_status = 500
        return web.Response(text=body, status=resp_status)

    async def post_lifting(self, request: aiohttp.web.BaseRequest) -> web.Response:
        return await self.handler(self.lifting, request)

    async def post_decompile(self, request: aiohttp.web.BaseRequest) -> web.Response:
        return await self.handler(self.decompile, request)

    async def get_version(self, request: aiohttp.web.BaseRequest) -> web.Response:
        try:
            version = self.version()
            resp_status = 200
        except:
            version = traceback.format_exc()
            resp_status = 500
        return web.Response(text=version, status=resp_status)


def mdec_main(service: Service):
    """
    Common module main function
    """
    ap = argparse.ArgumentParser()
    ap.add_argument('file', nargs='?', help='If provided, decompile given file and exit. Otherwise, start server')
    args = ap.parse_args()

    s = service()
    if args.file:
        print(s.decompile(args.file))
    else:
        web.run_app(s.app, port=8000)
