#!/usr/bin/env python
#
# Copyright 2015 clowwindy
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

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
                    if n >= 80:
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
