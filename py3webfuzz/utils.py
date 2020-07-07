#!/usr/bin/env python

""" This is the fuzzutils package. This contains useful items for performing
your fuzzing tasks agaist web applications

(c) 2020

Email: Jonathan Angeles, jangelesg{at}gangsecurity{dot}com
        'Nathan Hamiel, nathan{at}neohaxor{dot}org ,
        Hexsec Labs: http://hexsec.com/labs

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>
"""

import datetime
# from impacket.ntlm import compute_lmhash, compute_nthash
# from getpass import getpass
import http.server
# from bs4 import BeautifulSoup
# import functools
import logging
import ssl

import requests
from impacket import smbserver
from requests.exceptions import HTTPError, SSLError
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


def make_request(url, method, **kwargs):
    """
    This provides a convenience function for making requests. This interfaces with requests  which in turn interfaces
    with urllib3 and provides the ability to make GET, POST, PUT, PATCH and DELETE requests.

    The return data from this function is A DIC with HTTP Status Code, HTTP Headers, HTTP Content, JSON in case, Time,
    HTTP TEXT Content, timedelta from a successful request
    """

    # Checks to ensure that HTTP methods are valid  and header values and postdata are in the appropriate format

    METHODS = "put", "get", "post", "patch", "delete"

    assert (
            method in METHODS
    ), f"HTTP Method is not valid in the function, Valid Methods {METHODS}"

    def manage_arguments():
        """This provides a convenience function to manage and select the necessary parameters for the request
        """

        parameters = {"url": url}  # Creating parameters starting with the url
        parameters.update({"verify": False})  # DEFAULT SSL VERIFICATION DISABLE
        for _ in kwargs.keys():  # Selecting and Adding parameters from arguments
            if _ == "headers":
                parameters.update({"headers": kwargs["headers"]})
            if _ == "params":
                parameters.update({"params": kwargs["params"]})
            if _ == "data":
                parameters.update({"data": kwargs["data"]})
            if _ == "allow_redirects":
                parameters.update({"allow_redirects": kwargs["allow_redirects"]})
            if _ == "json":
                parameters.update({"json": kwargs["json"]})
            if _ == "proxies":
                # If proxies parameters is present "verify" Parameter is added equal to "False" to avoid
                # SSL Certs Error and disable warnings
                try:
                    from urllib3.exceptions import InsecureRequestWarning
                except ImportError as er:
                    print(f"Import Error Occurred. {er}")
                else:
                    # Suppress only the single warning from urllib3 needed.
                    # requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
                    parameters.update({"proxies": kwargs["proxies"]})
                    parameters.update({"verify": False})
        ''':return a dictionary key values corresponding to HTTP request '''
        return parameters

    try:
        params = manage_arguments()

        req = {
            "post": requests.post,  # Selecting the appropriate requests Class Object HTTP method
            "patch": requests.patch,
            "put": requests.put,
            "get": requests.get,
            "delete": requests.delete,
        }.get(method, lambda: None)

        start = datetime.datetime.now()

        response = req(**params)

        #  An HTTPError will be raised for certain status codes. If the status code indicates a successful request,
        #  the program will proceed without that exception being raised.

        response.raise_for_status()

    except HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
        print(f"{response.text}")
        exit(1)
    except Exception as err:
        print(f"Exception occurred: {err}")
        exit(1)
    except SSLError as sslerr:
        print(f"SSLError error occurred: {sslerr}")
        exit(1)
    else:
        end = datetime.datetime.now()
        time = end - start

        # Grab the HTTP Status Code, HTTP Headers, HTTP Content, JSON in case, Time, HTTP TEXT Content, response time
        # Return a dictionary whit those values

        return {
            "headers": response.headers,
            "content": response.content,
            "status_code": response.status_code,
            'json': response.json,
            "text": response.text,
            "time": f"Total in seconds: {time}",
        }


def generate_range(start, stop, step=1, pre=None, post=None):
    """ Generate a range of values with optional stepping. Chars can be prepended or attached to
    the end of each value that is generated. """

    rangevals = range(start, stop, step)
    values = []

    try:
        if pre and post:
            for item in rangevals:
                values.append(pre + str(item) + post)
            return values
        elif pre:
            for item in rangevals:
                values.append(pre + str(item))
            return values
        elif post:
            for item in rangevals:
                values.append(str(item) + post)
            return values
        else:
            for item in rangevals:
                values.append(str(item))
            return values
    except:
        print("You did not specify all of the values necessary for this function")

        print("No errors found")


def replace(func):
    ''' Handy Function to replace values when developing an exploit '''

    def wrapper(payload, mode, *args):
        print(f"Before {payload}")
        payload = payload.replace(args[0], args[1])
        print(f"After {payload}")
        return payload

    return wrapper


def mutate(payload, mode, *args):
    if mode == "r":
        payload = payload.replace(args[0], args[1])
        return payload


def https_server(*args):
    # Command line to create a SSL Certificate
    # openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
    '''Handy Function to launch a Small HTTPS Server to server files running on Localhost on port 8180'''

    if len(args) < 2:
        ip = "localhost"
        port = 8180

    elif len(args) > 2:
        raise NameError("Parameter Exceed")
    else:
        ip = args[0]
        port = args[1]

    print("-:==========" + f" Simple HTTPS Server on {ip}:{port}" + " ==========:-\n")
    server_address = ip, port
    httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)
    httpd.socket = ssl.wrap_socket(
        httpd.socket,
        server_side=True,
        certfile="server.pem",
        ssl_version=ssl.PROTOCOL_TLSv1,
    )
    httpd.serve_forever()


def http_server(*args):
    '''Handy Function to launch a Small HTTP Server to server files running on Localhost on port 8180'''

    try:
        if len(args) < 2:
            ip = "localhost"
            port = 8180

        elif len(args) > 2:
            raise NameError("Parameter Exceed")
        else:
            ip = args[0]
            port = args[1]

        print(
            "-:==========" + f" Simple HTTP Server on {ip}:{port}" + " ==========:-\n"
        )
        server_address = ip, port
        httpd = http.server.HTTPServer(
            server_address, http.server.SimpleHTTPRequestHandler
        )

    except Exception as err:
        print(f"{err}")
    else:
        # Rock and roll
        httpd.serve_forever()


def smb_server(interface, port, sharePath):
    '''Handy Function to launch a Small SMB Server to server files running on Localhost on py3webfuzz_share'''

    print(
        "-:==========" + f" Simple SMB Server on {interface}:{port}" + " ==========:-\n"
    )
    try:
        comment = f"Share Folder"
        shareName = "py3webfuzz_share"
        logging.getLogger().setLevel(logging.INFO)
        server = smbserver.SimpleSMBServer(
            listenAddress=interface, listenPort=int(port)
        )
        server.addShare(shareName.upper(), sharePath, comment)
        server.setSMBChallenge("")
        server.setLogFile("")
    except Exception as err:
        print(f"{err}")

    else:
        # Rock and roll
        server.start()
