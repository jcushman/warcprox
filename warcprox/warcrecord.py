#
# warcprox/warc.py - assembles warc records
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

import StringIO
import re

import warcprox
from hanzo import warctools
from hanzo.warctools.warc import version_rx, nl_rx, bad_lines, header_rx, value_rx, type_rx, length_rx


class SignedWarcParser(warctools.warc.WarcParser):
    logger = logging.getLogger("warcprox.warcrecord.SignedWarcParser")

    def parse(self, stream, offset, line=None):
        """
            Same as WarcParser.parse(), except that headers are collected and stored to record.header_string,
            and object returned is a SignedWarcRecord instead of a WarcRecord.
        """
        # pylint: disable-msg=E1101
        errors = []
        version = None
        header_string = b''
        # find WARC/.*
        if line is None:
            line = stream.readline()

        while line:
            match = version_rx.match(line)

            if match:
                version = match.group('version')
                header_string += line
                if offset is not None:
                    offset += len(match.group('prefix'))
                break
            else:
                if offset is not None:
                    offset += len(line)
                if not nl_rx.match(line):
                    errors.append(('ignored line', line))
                    if len(errors) > bad_lines:
                        errors.append(('too many errors, giving up hope',))
                        return (None, errors, offset)
                line = stream.readline()
        if not line:
            if version:
                errors.append(('warc version but no headers', version))
            return (None, errors, offset)
        if line:
            content_length = 0
            content_type = None

            record = SignedWarcRecord(errors=errors, version=version)

            if match.group('nl') != b'\x0d\x0a':
                record.error('incorrect newline in version', match.group('nl'))

            if match.group('number') not in self.KNOWN_VERSIONS:
                record.error('version field is not known (%s)'
                             % (",".join(self.KNOWN_VERSIONS)),
                             match.group('number'))

            prefix = match.group('prefix')

            if prefix:
                record.error('bad prefix on WARC version header', prefix)

            #Read headers
            line = stream.readline()
            if not nl_rx.match(line):
                header_string += line
            while line and not nl_rx.match(line):

                #print 'header', repr(line)
                match = header_rx.match(line)
                if match:
                    if match.group('nl') != b'\x0d\x0a':
                        record.error('incorrect newline in header',
                                     match.group('nl'))
                    name = match.group('name').strip()
                    value = [match.group('value').strip()]
                    #print 'match',name, value

                    line = stream.readline()
                    if not nl_rx.match(line):
                        header_string += line
                    match = value_rx.match(line)
                    while match:
                        #print 'follow', repr(line)
                        if match.group('nl') != b'\x0d\x0a':
                            record.error('incorrect newline in follow header',
                                         line, match.group('nl'))
                        value.append(match.group('value').strip())
                        line = stream.readline()
                        if not nl_rx.match(line):
                            header_string += line
                        match = value_rx.match(line)

                    value = b" ".join(value)

                    record.headers.append((name, value))

                    if type_rx.match(name):
                        if value:
                            content_type = value
                        else:
                            record.error('invalid header', name, value)
                    elif length_rx.match(name):
                        try:
                            #print name, value
                            content_length = int(value)
                            #print content_length
                        except ValueError:
                            record.error('invalid header', name, value)

            # have read blank line following headers

            record.content_file = stream
            record.content_file.bytes_to_eoc = content_length

            record.header_string = header_string

            # check mandatory headers
            # WARC-Type WARC-Date WARC-Record-ID Content-Length

            return (record, (), offset)


@warctools.WarcRecord.HEADERS(
    HEADER_SIGNATURE=b'WARC-Header-Signature'
)
class SignedWarcRecord(warctools.WarcRecord):
    def __init__(self, *args, **kwargs):
        self.signer = kwargs.pop('signer', None)
        self.header_string = None
        super(SignedWarcRecord, self).__init__(*args, **kwargs)

    @classmethod
    def make_parser(self):
        return SignedWarcParser()

    def _write_to(self, out, nl):
        """
            Same as WarcRecord._write_to, except that headers are collected in a separate buffer and passed to
            self._write_headers for signing and writing.
        """
        header = StringIO.StringIO()
        header.write(self.version)
        header.write(nl)
        for k, v in self.headers:
            if self.content_file is not None or k not in (self.CONTENT_TYPE, self.CONTENT_LENGTH):
                header.write(k)
                header.write(b": ")
                header.write(v)
                header.write(nl)

        if self.content_file is not None:
            self._write_headers(out, nl, header)
            while True:
                buf = self.content_file.read(8192)
                if buf == b'': break
                out.write(buf)
        else:
            # if content tuple is provided, set Content-Type and
            # Content-Length based on the values in the tuple
            content_type, content_buffer = self.content

            if content_type:
                header.write(self.CONTENT_TYPE)
                header.write(b": ")
                header.write(content_type)
                header.write(nl)
            if content_buffer is None:
                content_buffer = b""

            content_length = len(content_buffer)
            header.write(self.CONTENT_LENGTH)
            header.write(b": ")
            header.write(str(content_length).encode('ascii'))
            header.write(nl)

            self._write_headers(out, nl, header)
            if content_buffer:
                out.write(content_buffer)

        # end of record nl nl
        out.write(nl)
        out.write(nl)
        out.flush()

    def _write_headers(self, out, nl, header):
        unsigned_header_string = header.getvalue()
        if self.signer:
            header.write(self.HEADER_SIGNATURE)
            header.write(b": ")
            header.write(self.get_signature(unsigned_header_string))
            header.write(nl)
        self.header_string = header.getvalue()
        out.write(self.header_string)
        out.write(nl)  # end of header blank nl

    def get_signature(self, header):
        """
            Insert WARC-Header-Signature header into headers, signing existing headers.
        """
        return b'%s:%s;pk=%s' % (
            self.signer.algorithm,
            self.signer.sign(header),
            self.signer.get_public_key())

    def verify_signature(self):
        """
            Return true if record has a valid header signature.

            NOTE: This does not verify block or payload digests contained in the header.
        """
        if not self.header_string:
            return (False, "No header_string available to verify (typically set during writing or parsing record).")
        signature_header = self.get_header(self.HEADER_SIGNATURE)
        if not signature_header:
            return (False, "No %s header to verify." % self.HEADER_SIGNATURE)
        parts = re.match(r'(.+)\:(.+);pk=(.+)', signature_header)
        if not parts:
            return (False, "Signature does not match expected pattern: <algorithm>:<signature>;pk=<pk>")
        algorithm, signature, public_key = parts.groups()
        signer_class = warcprox.warcsigner.signers.get(algorithm)
        if not signer_class:
            return (False, "Unknown signature algorithm %s" % algorithm)
        signer = signer_class(public_key=public_key)
        unsigned_header_string = re.sub(r'^%s: .*\n' % self.HEADER_SIGNATURE, '', self.header_string, flags=re.M)
        is_valid = signer.verify(unsigned_header_string, signature)
        if not is_valid:
            return (False, "Signature does not validate.")
        return (True, None)
