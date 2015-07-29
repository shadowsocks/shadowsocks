#!/usr/bin/env python

if __name__ == '__main__':
    import tornado.ioloop
    import tornado.web
    import urllib

    class MainHandler(tornado.web.RequestHandler):
        def get(self, project):
            try:
                with open('/tmp/%s-coverage' % project, 'rb') as f:
                    coverage = f.read().strip()
                    n = int(coverage.strip('%'))
                    if n > 80:
                        color = 'brightgreen'
                    else:
                        color = 'yellow'
                    self.redirect(('https://img.shields.io/badge/'
                                   'coverage-%s-%s.svg'
                                   '?style=flat') %
                                  (urllib.quote(coverage), color))
            except IOError:
                raise tornado.web.HTTPError(404)

    application = tornado.web.Application([
        (r"/([a-zA-Z0-9\-_]+)", MainHandler),
    ])

    if __name__ == "__main__":
        application.listen(8888, address='127.0.0.1')
        tornado.ioloop.IOLoop.instance().start()
