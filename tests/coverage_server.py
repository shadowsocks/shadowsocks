#!/usr/bin/env python

if __name__ == '__main__':
    import tornado.ioloop
    import tornado.web
    import urllib

    class MainHandler(tornado.web.RequestHandler):
        def get(self):
            with open('/tmp/shadowsocks-coverage', 'rb') as f:
                coverage = f.read().strip()
                self.redirect(('https://img.shields.io/badge/'
                               'coverage-%s-brightgreen.svg'
                               '?style=flat') %
                              urllib.quote(coverage))

    application = tornado.web.Application([
        (r"/shadowsocks", MainHandler),
    ])

    if __name__ == "__main__":
        application.listen(8888, address='127.0.0.1')
        tornado.ioloop.IOLoop.instance().start()
