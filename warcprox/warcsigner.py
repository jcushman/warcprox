#
# warcprox/warcsigner.py - signers for warc records
#
# Copyright (C) 2013-2016 Internet Archive
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
# USA.
#

from __future__ import absolute_import

import logging
import nacl.signing
import nacl.encoding
import nacl.exceptions


class WarcSigner:
    """ Base signer. """
    logger = logging.getLogger("warcprox.warc.WarcSigner")
    algorithm = None

    def __init__(self, private_key=None, public_key=None):
        if not private_key and not public_key:
            raise ValueError("One of private_key or public_key is required.")
        self.private_key = private_key
        self.public_key = public_key

    def sign(self, message):
        raise NotImplementedError

    def verify(self, message, signature):
        raise NotImplementedError

    def get_public_key(self):
        raise NotImplementedError

class Ed25519Signer(WarcSigner):
    algorithm = 'ed25519'

    def __init__(self, *args, **kwargs):
        WarcSigner.__init__(self, *args, **kwargs)
        if self.private_key:
            self.signing_key = nacl.signing.SigningKey(self.private_key, nacl.encoding.HexEncoder)
            self.verify_key = self.signing_key.verify_key
        else:
            self.signing_key = None
            self.verify_key = nacl.signing.VerifyKey(self.public_key, nacl.encoding.HexEncoder)

    def sign(self, message):
        if not self.signing_key:
            raise ValueError("Canot sign messages without private_key.")
        return self.signing_key.sign(message, nacl.encoding.HexEncoder).signature

    def verify(self, message, signature):
        try:
            self.verify_key.verify(bytes(message), nacl.encoding.HexEncoder.decode(signature))
            return True
        except nacl.exceptions.BadSignatureError:
            return False

    def get_public_key(self):
        return self.signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)

signers = {
    Ed25519Signer.algorithm: Ed25519Signer
}