'''


'''
if __name__ == "__main__":
    # Import Library
    from py3webfuzz import fuzzdb, encoderFuncs

    # Instantiate a Class Object that give you access to a set of SQLi values
    sqli_detect_payload = fuzzdb.Attack.AttackPayloads.SQLi.Detect()
    # Getting Access to those values through a list
    for index, payload in enumerate(sqli_detect_payload.Generic_SQLI):
        print(f"Payload: {index} Value: {payload}")
        # Using encoderFuncs you can get different handy encodings to develop exploits

        print(f"SQLi Char Encode: {encoderFuncs.sqlchar_encode(payload)}")


