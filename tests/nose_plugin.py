import nose
from nose.plugins.base import Plugin


class ExtensionPlugin(Plugin):

    name = "ExtensionPlugin"

    def options(self, parser, env):
        Plugin.options(self, parser, env)

    def configure(self, options, config):
        Plugin.configure(self, options, config)
        self.enabled = True

    def wantFile(self, file):
        return file.endswith('.py')

    def wantDirectory(self, directory):
        return True

    def wantModule(self, file):
        return True


if __name__ == '__main__':
    nose.main(addplugins=[ExtensionPlugin()])
