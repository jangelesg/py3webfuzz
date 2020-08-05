'''


'''
if __name__ == "__main__":
    # Import Library
    from py3webfuzz import fuzzdb, encoderFuncs

    # Instantiate a Class Object that give you access to a set of SQLi values
    extended_payload = fuzzdb.Extended()
    # Getting Access to those values through a list
    for index, payload in enumerate(extended_payload.ssti_payloads):
        print(f"Payload: {index} Value: {payload}")

        # Using encoderFuncs you can get different handy encodings to develop exploits
        print(f"SSTI Char Encode: {encoderFuncs.sqlchar_encode(payload)}")


