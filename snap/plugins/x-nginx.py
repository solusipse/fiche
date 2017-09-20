# -*- Mode:Python; indent-tabs-mode:nil; tab-width:4 -*-
#
# Copyright (C) 2017 James Beedy <jamesbeedy@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 3 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""The nginx plugin is useful for web app based parts.
    - nginx-version:
      (string)
      The version of nginx you want this snap to run.
    - pcre-version:
      (string)
      The version of pcre you want to compile nginx with.
    - openssl-version:
      (string)
      The version of openssl you want to compile nginx with.
    - zlib-version:
      (string)
      The version of zlib you want to compile nginx with.
    - use-passenger
      (boolean)
      Compile nginx with passenger module. (Defaults to false)
"""
import logging
import os
import platform
import re

from snapcraft import BasePlugin, file_utils
from snapcraft.sources import Tar


logger = logging.getLogger(__name__)


class NginxPlugin(BasePlugin):

    @classmethod
    def schema(cls):
        schema = super().schema()

        schema['properties']['nginx-version'] = {
            'type': 'string',
            'default': '1.11.13'
        }
        schema['properties']['pcre-version'] = {
            'type': 'string',
            'default': '8.40'
        }
        schema['properties']['zlib-version'] = {
            'type': 'string',
            'default': '1.2.11'
        }
        schema['properties']['openssl-version'] = {
            'type': 'string',
            'default': '1.0.2f'
        }
        schema['properties']['use-passenger'] = {
            'type': 'boolean',
            'default': False
        }
        return schema

    @classmethod
    def get_pull_properties(cls):
        # Inform Snapcraft of the properties associated with pulling. If these
        # change in the YAML Snapcraft will consider the build step dirty.
        return ['nginx-version', 'pcre-version', 'zlib-version', 'openssl-version']

    def __init__(self, name, options, project):
        super().__init__(name, options, project)
        # Beta Warning
        # Remove this comment and warning once nginx plugin is stable.
        logger.warn("The nginx plugin is currently in beta, "
                    "its API may break. Use at your own risk")

        # NGINX bits
        self._nginx_download_url = \
            'http://nginx.org/download/nginx-{}.tar.gz'.format(
                self.options.nginx_version)
        self._nginx_part_dir = os.path.join(self.partdir, 'nginx')
        self._nginx_tar = Tar(self._nginx_download_url, self._nginx_part_dir)

        # PCRE 
        self._pcre_download_url = \
            'ftp://ftp.csx.cam.ac.uk/pub/software/programming/pcre/pcre-{}.tar.gz'.format(
                self.options.pcre_version)
        self._pcre_part_dir = os.path.join(self.partdir, 'pcre')
        self._pcre_tar = Tar(self._pcre_download_url, self._pcre_part_dir)

        # OPENSSL
        self._openssl_download_url = \
            'http://www.openssl.org/source/openssl-{}.tar.gz'.format(
                self.options.openssl_version)
        self._openssl_part_dir = os.path.join(self.partdir, 'openssl')
        self._openssl_tar = Tar(self._openssl_download_url, self._openssl_part_dir)

        # ZLIB
        self._zlib_download_url = \
            'http://zlib.net/zlib-{}.tar.gz'.format(
                self.options.zlib_version)
        self._zlib_part_dir = os.path.join(self.partdir, 'zlib')
        self._zlib_tar = Tar(self._zlib_download_url, self._zlib_part_dir)

        # PASSENGER
        if self.options.use_passenger:
            self._passenger_download_url = \
                'https://www.phusionpassenger.com/latest_stable_tarball'
            self._passenger_part_dir = os.path.join(self.partdir, 'passenger')
            self._passenger_tar = Tar(self._passenger_download_url,
                                      self._passenger_part_dir)

        self.build_packages.extend(['gcc', 'g++', 'make',
                                    'ruby-dev', 'libcurl4-openssl-dev'])

    def snap_fileset(self):
        fileset = super().snap_fileset()
        fileset.append('-include/')
        fileset.append('-share/')
        return fileset

    def pull(self):
        super().pull()
        # PCRE
        os.makedirs(self._pcre_part_dir, exist_ok=True)
        self._pcre_tar.download()
        self._pcre_install(builddir=self._pcre_part_dir)

        # ZLIB
        os.makedirs(self._zlib_part_dir, exist_ok=True)
        self._zlib_tar.download()
        self._zlib_install(builddir=self._zlib_part_dir)

        # OPENSSL
        os.makedirs(self._openssl_part_dir, exist_ok=True)
        self._openssl_tar.download()
        self._openssl_install(builddir=self._openssl_part_dir)

        # PASSENGER
        if self.options.use_passenger:
            os.makedirs(self._passenger_part_dir, exist_ok=True)
            self._passenger_tar.download()
            self._passenger_install(builddir=self._passenger_part_dir)

        # NGINX
        os.makedirs(self._nginx_part_dir, exist_ok=True)
        self._nginx_tar.download()
        self._nginx_install(builddir=self._nginx_part_dir)

    def env(self, root):
        env = super().env(root)
        env.append('PATH={}:{}'.format(
            os.path.join(root, 'bin'), os.environ['PATH']))
        return env

    def _pcre_install(self, builddir):
        self._pcre_tar.provision(
            builddir, clean_target=False, keep_tarball=True)
        self.run(['./configure'], cwd=builddir)
        self.run(['make', '-j{}'.format(self.parallel_build_count)],
                 cwd=builddir)
        self.run(['make', 'install'], cwd=builddir)

    def _zlib_install(self, builddir):
        self._zlib_tar.provision(
            builddir, clean_target=False, keep_tarball=True)
        self.run(['./configure'], cwd=builddir)
        self.run(['make', '-j{}'.format(self.parallel_build_count)],
                 cwd=builddir)
        self.run(['make', 'install'], cwd=builddir)

    def _openssl_install(self, builddir):
        self._openssl_tar.provision(
            builddir, clean_target=False, keep_tarball=True)
        self.run(['./config', '--prefix=/'], cwd=builddir)
        self.run(['make', '-j{}'.format(self.parallel_build_count)],
                 cwd=builddir)
        self.run(['make', 'install'], cwd=builddir)

    def _passenger_install(self, builddir):
        self._passenger_tar.provision(
            builddir, clean_target=False, keep_tarball=True)

    def _nginx_install(self, builddir):
        self._nginx_tar.provision(
            builddir, clean_target=False, keep_tarball=True)
        cmd = ['./configure',
               '--sbin-path={}'.format(os.path.join(
                   self.installdir, 'nginx', 'sbin', 'nginx')),
               '--conf-path={}'.format(os.path.join(
                  self.installdir, 'nginx', 'conf', 'nginx.conf')),
               '--with-pcre={}'.format(self._pcre_part_dir),
               '--with-zlib={}'.format(self._zlib_part_dir),
               '--with-http_ssl_module',
               '--with-http_gzip_static_module',
               '--with-stream']
        if self.options.use_passenger:
            cmd.append('--add-module={}'.format(os.path.join(
                self._passenger_part_dir, 'src', 'nginx_module')))
        self.run(cmd, cwd=builddir)
        self.run(['make', '-j{}'.format(self.parallel_build_count)],
                 cwd=builddir)
        self.run(['make', 'install'], cwd=builddir)
