if __name__ == "__main__":
    from py3webfuzz import encoderFuncs

    print("Full URL: ", encoderFuncs.full_hex_url_encode('%48%65%6c%6c%6f%20%57%6f%72%6c%64'))
    print("BASE64: ", encoderFuncs.base64_encode('sasa'))
    print("URL ENCODE: ", encoderFuncs.url_encode('hello world'))
    print('html_entity_encode', encoderFuncs.html_entity_encode("""& < " ' >"""))
    print('hex_encode', encoderFuncs.hex_encode("68656c6c6f"))
    print('hex_entity_encode', encoderFuncs.hex_entity_encode("&param=1"))
    print('unicode_encode', encoderFuncs.unicode_encode("&param=1"))
    print('escape_xml', encoderFuncs.escape_xml("&param=1"))
    print('md5_hash', encoderFuncs.md5_hash("nimda"))
    print('sha1_hash', encoderFuncs.sha1_hash("nimda"))
    print('sqlchar_encode', encoderFuncs.sqlchar_encode("nimda"))
    print('oraclechr_encode', encoderFuncs.oraclechr_encode("nimda"))
    print('decimal_convert', encoderFuncs.decimal_convert("nimda"))
    print('decimal_entity_encode', encoderFuncs.decimal_entity_encode("nimda"))
    print('rot13_encode', encoderFuncs.rot13_encode("nimda"))

    print('************************')

    print('url_decode', encoderFuncs.url_decode("Hello%20World"))
    print('fullurl_decode', encoderFuncs.full_hex_url_decode("%48%65%6c%6c%6f%20%57%6f%72%6c%64"))
    print('base64_decode', encoderFuncs.base64_decode("%SGVsbG8gV29ybGQ="))
    print('hex_decode', encoderFuncs.hex_decode("68656c6c6f"))
    print('hexentity_decode', encoderFuncs.hexentity_decode("&#x48;&#x65;&#x6c;&#x6c;&#x6f;"))
    print('unescape_xml', encoderFuncs.unescape_xml("Hello&amp;World"))
    print('unicode_decode',
          encoderFuncs.unicode_decode("%u0048%u0065%u006c%u006c%u006f%u0020%u0057%u006f%u0072%u006c%u0064"))
    print('rot13_decode', encoderFuncs.rot13_decode("Uryyb Jbeyq"))
