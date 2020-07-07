#!/usr/bin/env python

"""
This is the encoding / decoding functions collection for Encoder. It
allows you to encode and decode various data formats.

(c) 2020
- Nathan Hamiel @nathanhamiel
- Jonathan Angeles @ex0day

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import urllib.parse
import hashlib
import base64
import html
import codecs
from xml.sax.saxutils import unescape
from xml.sax.saxutils import escape


###################
# Encoder section #
###################


def url_encode(encvalue: str):
    """ URL encode the specifed value. Example Format: Hello%20World
    The quote() function accepts a named parameter called safe whose default value is /. If you want to encode / character as well,
    then you can do so by supplying an empty string in the safe parameter like this-
    """

    try:
        encoded_value = urllib.parse.quote(encvalue)
    except Exception as e:
        print(f"Exception trying to encode {encvalue}, Error: {e}")
    else:
        return encoded_value


def full_hex_url_encode(encvalue):
    """ Full URL Hex encode the specified value.
    Example Format: %48%65%6c%6c%6f%20%57%6f%72%6c%64 """

    hexval = ""

    for item in encvalue:
        val = hex(ord(item)).replace("0x", "%")
        hexval += val

    return hexval


def base64_encode(encvalue: str):
    """ Base64 encode the specified value. Example Format: SGVsbG8gV29ybGQ= """
    try:
        basedata = base64.b64encode(encvalue.encode(encoding="utf-8")).decode(
            encoding="utf-8"
        )
    except Exception as e:
        print(f"Exception trying to encode {encvalue}, Error: {e}")
    else:
        return basedata


def html_entity_encode(encvalue):
    """ Encode value using HTML entities. Example Format:  """
    encoded_value = html.escape(encvalue)
    return encoded_value


def hex_encode(encvalue: int):
    """Encode value to Hex. Example Format: 48656c6c6f2576f726c64"""
    hexval = ""
    for item in encvalue:
        val = hex(ord(item)).strip("0x")
        hexval += val
    return hexval


def hex_entity_encode(encvalue: str):
    """ Encode value to a Hex entitiy. Example Format: &#x48;&#x65;&#x6c;&#x6c;&#x6f;"""
    hexval = ""
    for item in encvalue:
        val = hex(ord(item)).replace("0x", "&#x") + ";"
        hexval += val
    return hexval


def unicode_encode(encvalue):
    """ Unicode encode the specified value in the %u00 format. Example:
    %u0048%u0065%u006c%u006c%u006f%u0020%u0057%u006f%u0072%u006c%u0064 """
    hexval = ""
    for item in encvalue:
        val = hex(ord(item)).replace("0x", "%u00")
        hexval += val
    return hexval


def escape_xml(encvalue):
    """ Escape the specified HTML/XML value. Example Format: Hello&amp;World """
    escaped = escape(encvalue, {"'": "&apos;", '"': "&quot;"})
    return escaped


def md5_hash(encvalue: str):
    """ md5 hash the specified value.
    Example Format: b10a8db164e0754105b7a99be72e3fe5"""
    hashdata = hashlib.md5(encvalue.encode('utf-8')).hexdigest()
    return hashdata


def sha1_hash(encvalue: str):
    """ sha1 hash the specified value.
    Example Format: 0a4d55a8d778e5022fab701977c5d840bbc486d0 """
    hashdata = hashlib.sha1(encvalue.encode('utf-8')).hexdigest()
    return hashdata


def sqlchar_encode(encvalue: str):
    """ SQL char encode the specified value.
    Example Format: CHAR(72)+CHAR(101)+CHAR(108)+CHAR(108)+CHAR(111)"""
    charstring = ""
    for item in encvalue:
        val = "CHAR(" + str(ord(item)) + ")+"
        charstring += val
    return charstring.rstrip("+")


def oraclechr_encode(encvalue):
    """ Oracle chr encode the specified value. """
    charstring = ""
    for item in encvalue:
        val = "chr(" + str(ord(item)) + ")||"
        charstring += val
    return charstring.rstrip("||")


def decimal_convert(encvalue):
    """ Convert input to decimal value.
    Example Format: 721011081081113287111114108100 """
    decvalue = ""
    for item in encvalue:
        decvalue += str(ord(item))

    return decvalue


def decimal_entity_encode(encvalue):
    """ Convert input to a decimal entity.
    Example Format: &#72;&#101;&#108;&#108;&#111;&#32;&#87;&#111;&#114;&#108;&#100; """

    decvalue = ""

    for item in encvalue:
        decvalue += "&#" + str(ord(item)) + ";"

    return decvalue


def rot13_encode(encvalue: str):
    """ Perform ROT13 encoding on the specified value.
    Example Format: Uryyb Jbeyq """
    return codecs.encode(encvalue, "rot13")


###################
# Decoder section #
###################


def url_decode(decvalue: str):
    """ URL Decode the specified value. Example Format: Hello%20World """
    returnval = urllib.parse.unquote(decvalue)
    return returnval


def full_hex_url_decode(decvalue: str):
    """ Full URL decode the specified value.
    Example Format: %48%65%6c%6c%6f%20%57%6f%72%6c%64 """
    splithex = decvalue.split("%")
    hexdec = ""
    for item in splithex:
        if item != "":
            hexdec += chr(int(item, 16))
    return hexdec


def base64_decode(decvalue: str):
    """ Base64 decode the specified value.
    Example Format: SGVsbG8gV29ybGQ= """
    try:
        base64dec = base64.b64decode(decvalue).decode('utf-8')
    except Exception as e:
        print(f"Exception trying to encode {decvalue}, Error: {e}")
    else:
        return base64dec


def hex_decode(decvalue):
    """ Hex decode the specified value.
    Example Format: 68656c6c6f """

    try:
        decodeval = codecs.decode(decvalue, "hex").decode('utf-8')
    except Exception as e:
        print(f"Exception trying to encode {decvalue}, Error: {e}")
    else:
        return decodeval


def hexentity_decode(decvalue):
    """ Hex entity decode the specified value.
    Example Format: &#x48;&#x65;&#x6c;&#x6c;&#x6f; """
    charval = ""
    splithex = decvalue.split(";")

    for item in splithex:
        # Necessary because split creates an empty "" that tries to be
        # converted with int()
        if item != "":
            hexcon = item.replace("&#", "0")
            charcon = chr(int(hexcon, 16))
            charval += charcon
        else:
            pass

    return charval


def unescape_xml(decvalue):
    """ Unescape the specified HTML or XML value: Hello&amp;World"""
    try:
        unescaped = unescape(decvalue, {"&apos;": "'", "&quot;": '"'})
    except Exception as e:
        print(f"Exception trying to encode {decvalue}, Error: {e}")
    else:
        return unescaped


def unicode_decode(decvalue):
    """ Unicode decode the specified value %u00 format. 
    Example Format: %u0048%u0065%u006c%u006c%u006f%u0020%u0057%u006f%u0072%u006c%u0064 """
    charval = ""
    splithex = decvalue.split("%u00")
    try:
        for item in splithex:
            if item != "":
                hexcon = item.replace("%u00", "0")
                charcon = chr(int(hexcon, 16))
                charval += charcon
            else:
                pass
    except Exception as e:
        print(f"Exception trying to encode {decvalue}, Error: {e}")
    else:
        return charval


def rot13_decode(decvalue):
    """ ROT13 decode the specified value. Example Format: Uryyb Jbeyq  """
    try:
        rot13decval = codecs.decode(decvalue, 'rot13')
    except Exception as e:
        print(f"Exception trying to encode {decvalue}, Error: {e}")
    else:
        return rot13decval
