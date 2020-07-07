"""
Authors:
        Nathan Hamiel @nathanhamiel, Jonathan Angeles @ex0day

Based on "pywebfuzz" This module "py3webfuzz" is compatible with python3, uses logic to implement values from the fuzzdb
project along with some others handy values and tools to write crafted web exploits

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

# Libraries Required
import os
import logging


class Attack:
    """ Main Fuzzdb Attack Class """

    def __str__(self):
        return "Main Fuzzdb Attack Class"

    def __repr__(self):
        return f"{__name__}{self.__class__.__name__}"

    MODPATH = os.path.dirname(__file__)

    @staticmethod
    def file_read(location):
        """ Read the file contents and return the results values, Used in the construction of the values for the payload lists """
        logging.basicConfig(level=logging.DEBUG)
        logger = logging.getLogger(__name__)
        path = Attack.MODPATH + location

        try:
            assert os.access(path, os.R_OK), f"Error Accessing the file {location}"
            with open(path, "rb") as file:
                val = list()
                #  safely read in binary mode and decode it in utf8 with ignore mod
                lines = [l.decode("utf-8", "ignore") for l in file.readlines()]
                for item in lines:
                    if item.startswith("# ") or item.startswith("\n"):
                        pass
                    else:
                        val.append(item.rstrip())
                return val
        except Exception as e:
            print(f"[x] Exception Occurred {e}")
            logger.exception(e)
            exit(1)

    @staticmethod
    def image_read(location):
        path = Attack.MODPATH + location

    class AttackPayloads:
        """ AttackPayloads Object , Placeholder namespace for the attack payloads"""

        def __str__(self):
            return "Placeholder namespace for the attack payloads"

        def __repr__(self):
            return f"{self.__class__.__name__}"

        class AllAttacks:
            """ This Class implements the all-attacks values from fuzzdb"""

            def __init__(self):
                # all-attacks-unix.txt
                location = "/web/data/fuzzdb/attack/all-attacks/all-attacks-unix.txt"
                self.all_attacks_unix = Attack.file_read(location)

                # all-attacks-win.txt
                location = "/web/data/fuzzdb/attack/all-attacks/all-attacks-win.txt"
                self.all_attacks_win = Attack.file_read(location)

                # all-attacks-xplatform.txt
                location = (
                    "/web/data/fuzzdb/attack/all-attacks/all-attacks-xplatform.txt"
                )
                self.interesting_metacharacters = Attack.file_read(location)

            def __repr__(self):
                return (
                    f"{self.__class__.__name__} {self.all_attacks_win!r} {self.all_attacks_unix!r},"
                    f" {self.interesting_metacharacters!r}"
                )

        class BizLogic:
            """  This implements the items from the business-logic directory from fuzzdb """

            def __str__(self):
                return " This implements the items from the business-logic directory from fuzzdb "

            def __repr__(self):
                return (
                    "{self.__class__.__name__}({self.CommonDebugParamNames}, "
                    "{self.CommonMethodNames}, {self.DebugParamsJsonfuzz})".format(
                        self=self
                    )
                )

            def __init__(self):
                # business-logic
                location = (
                    "/web/data/fuzzdb/attack/business-logic/CommonDebugParamNames.txt"
                )
                self.CommonDebugParamNames = Attack.file_read(location)

                location = (
                    "/web/data/fuzzdb/attack/business-logic/CommonMethodNames.txt"
                )
                self.CommonMethodNames = Attack.file_read(location)

                location = (
                    "/web/data/fuzzdb/attack/business-logic/DebugParams.Json.fuzz.txt"
                )
                self.DebugParamsJsonfuzz = Attack.file_read(location)

        class ControlChars:
            """  This implements the control-chars directory from fuzzdb """

            def __str__(self):
                return " This implements the control-chars directory from fuzzdb "

            def __repr__(self):
                return (
                    "{self.__class__.__name__}({self.HexValsAllBytes}, {self.null_fuzz}, "
                    "{self.imessage} )".format(self=self)
                )

            def __init__(self):
                # null.fuzz
                location = "/web/data/fuzzdb/attack/control-chars/HexValsAllBytes.txt"
                self.HexValsAllBytes = Attack.file_read(location)

                location = (
                    "/web/data/fuzzdb/attack/control-chars/NullByteRepresentations.txt"
                )
                self.null_fuzz = Attack.file_read(location)

                location = "/web/data/fuzzdb/attack/control-chars/imessage.txt"
                self.imessage = Attack.file_read(location)

        class DisclosureDirectory:
            """ This implements the disclosure-directory from fuzzdb """

            # REPR AND STR
            def __init__(self):
                # directory-indexing-generic.txt
                location = "/web/data/fuzzdb/attack/disclosure-directory/directory-indexing-generic.txt"
                self.directory_indexing_generic = Attack.file_read(location)

        class DisclosureLocalPaths:
            """ This implements the disclosure-local-path from fuzzdb """

            """ This implements the unix payloads from fuzzdb """

            def __init__(self):
                location = "/web/data/fuzzdb/attack/disclosure-localpaths/unix/common-unix-httpd-log-locations.txt"
                self.common_unix_httpd_log_locations = Attack.file_read(location)

                """ This implements the win payloads from fuzzdb"""
                # This class is currently empty

        class DisclosureSource:
            """ This implements the disclosure-source from fuzzdb """

            def __init__(self):
                # source-disc-cmd-exec-traversal
                location = "/web/data/fuzzdb/attack/disclosure-source/source-disc-cmd-exec-traversal.txt"
                self.source_disc_cmd_exec_traversal = Attack.file_read(location)

                # source-disclosure-generic.txt
                location = "/web/data/fuzzdb/attack/disclosure-source/source-disclosure-generic.txt"
                self.source_disclosure_generic = Attack.file_read(location)

                # source-disclosure-microsoft.txt
                location = "/web/data/fuzzdb/attack/disclosure-source/source-disclosure-microsoft.txt"
                self.source_disclosure_microsoft = Attack.file_read(location)

        class Email:
            """This implement the Email payloads from FUZZDB """

            def __init__(self):
                location = "/web/data/fuzzdb/attack/email/invalid-email-addresses.txt"
                self.invalid_email_addresses = Attack.file_read(location)

                location = "fuzzdb/attack/email/valid-email-addresses.txt"
                self.valid_email_addresses = Attack.file_read(location)

        class FileUpload:
            """ This implement the file upload payloads from FuzzDB"""

            def __init__(self):
                # all-extensions-asp
                location = "/web/data/fuzzdb/attack/file-upload/alt-extensions-asp.txt"
                self.alt_extensions_asp = Attack.file_read(location)

                location = (
                    "/web/data/fuzzdb/attack/file-upload/alt-extensions-coldfusion.txt"
                )
                self.alt_extensions_coldfusion = Attack.file_read(location)

                location = "/web/data/fuzzdb/attack/file-upload/alt-extensions-jsp.txt"
                self.alt_extensions_jsp = Attack.file_read(location)

                location = "/web/data/fuzzdb/attack/file-upload/alt-extensions-perl.txt"
                self.alt_extensions_perl = Attack.file_read(location)

                location = "/web/data/fuzzdb/attack/file-upload/alt-extensions-php.txt"
                self.alt_extensions_php = Attack.file_read(location)

                location = "/web/data/fuzzdb/attack/file-upload/file-ul-filter-bypass-commonly-writable-directories.txt"
                self.file_ul_filter_bypass_commonly_writable_directories = Attack.file_read(
                    location
                )

                location = "/web/data/fuzzdb/attack/file-upload/file-ul-filter-bypass-microsoft-asp.txt"
                self.file_ul_filter_bypass_microsoft_asp = Attack.file_read(location)

                location = "/web/data/fuzzdb/attack/file-upload/file-ul-filter-bypass-microsoft-asp-filetype-bf.txt"
                self.file_ul_filter_bypass_microsoft_asp_filetype_bf = Attack.file_read(
                    location
                )

                location = "/web/data/fuzzdb/attack/file-upload/file-ul-filter-bypass-ms-php.txt"
                self.file_ul_filter_bypass_ms_php = Attack.file_read(location)

                location = "/web/data/fuzzdb/attack/file-upload/file-ul-filter-bypass-x-platform-generic.txt"
                self.file_ul_filter_bypass_x_platform_generic = Attack.file_read(
                    location
                )

                location = "/web/data/fuzzdb/attack/file-upload/file-ul-filter-bypass-x-platform-php.txt"
                self.file_ul_filter_bypass_x_platform_php = Attack.file_read(location)

                location = (
                    "/web/data/fuzzdb/attack/file-upload/invalid-filenames-linux.txt"
                )
                self.invalid_filenames_linux = Attack.file_read(location)

                location = "/web/data/fuzzdb/attack/file-upload/invalid-filenames-microsoft.txt"
                self.invalid_filenames_microsoft = Attack.file_read(location)

                location = "/web/data/fuzzdb/attack/file-upload/invalid-filesystem-chars-microsoft.txt"
                self.invalid_filesystem_chars_microsof = Attack.file_read(location)

                location = "/web/data/fuzzdb/attack/file-upload/invalid-filesystem-chars-osx.txt"
                self.invalid_filesystem_chars_osx = Attack.file_read(location)

            class MaliciousImages:
                def __init__(self):
                    location = "/web/data/fuzzdb/attack/file-upload/malicious-images/eicar.com.txt"
                    self.eicar_com = Attack.file_read(location)
                    # PENDING TO CODE

        class FormatStrings:
            """This implement the Format Strings payloads from FUZZDB """

            def __init__(self):
                location = "/web/data/fuzzdb/attack/format-strings/format-strings.txt"
                self.format_strings = Attack.file_read(location)

        class HtmlJSfuzz:
            """This implement the HTML JS FUZZ from FUZZDB """

            def __init__(self):
                location = (
                    "/web/data/fuzzdb/attack/html_js_fuzz/HTML5sec_Injections.txt"
                )
                self.HTML5sec_Injections = Attack.file_read(location)

                location = "/web/data/fuzzdb/attack/html_js_fuzz/html_attributes.txt"
                self.html_attributes = Attack.file_read(location)

                location = "/web/data/fuzzdb/attack/html_js_fuzz/html_tags.txt"
                self.html_tags = Attack.file_read(location)

                location = "/web/data/fuzzdb/attack/html_js_fuzz/javascript_events.txt"
                self.javascript_events = Attack.file_read(location)

                location = "/web/data/fuzzdb/attack/html_js_fuzz/js_inject.txt"
                self.js_inject = Attack.file_read(location)

                location = "/web/data/fuzzdb/attack/html_js_fuzz/quotationmarks.txt"
                self.quotation_marks = Attack.file_read(location)

        class HttpProtocol:
            """This implement the HTML Protocol from FUZZDB """

            def __init__(self):
                location = "/web/data/fuzzdb/attack/http-protocol/crlf-injection.txt"
                self.crlf_injection = Attack.file_read(location)

                location = "/web/data/fuzzdb/attack/http-protocol/hpp.txt"
                self.hpp = Attack.file_read(location)

                location = (
                    "/web/data/fuzzdb/attack/http-protocol/http-header-cache-poison.txt"
                )
                self.http_header_cache_poison = Attack.file_read(location)

                location = (
                    "/web/data/fuzzdb/attack/http-protocol/http-protocol-methods.txt"
                )
                self.http_protocol_methods = Attack.file_read(location)

                location = "/web/data/fuzzdb/attack/http-protocol/http-request-header-field-names.txt"
                self.http_request_header_field_names = Attack.file_read(location)

                location = "/web/data/fuzzdb/attack/http-protocol/http-response-header-field-names.txt"
                self.http_response_header_field_names = Attack.file_read(location)

                location = "/web/data/fuzzdb/attack/http-protocol/known-uri-types.txt"
                self.known_uri_types = Attack.file_read(location)

                location = "/web/data/fuzzdb/attack/http-protocol/user-agents.txt"
                self.user_agents = Attack.file_read(location)

            @staticmethod
            def cheat_sheet_http_protocol():
                """These tables contain a nearly complete list of all the methods, requests,
                and header fields of typical HTTP/1.0 and HTTP/1.1 requests and responses."""
                location = (
                    "/web/data/fuzzdb/attack/http-protocol/docs.http-method-defs.html"
                )
                docs_http_method_defs_html = Attack.file_read(location)
                return docs_http_method_defs_html

        class IntegerOverflow:
            """This implement the Integer Overflow from FUZZDB """

            def __init__(self):
                location = (
                    "/web/data/fuzzdb/attack/integer-overflow/integer-overflows.txt"
                )
                self.integer_overflow = Attack.file_read(location)

        class IP:
            """This implement the various formats of IP LOCALHOST from FUZZDB """

            def __init__(self):
                location = "/web/data/fuzzdb/attack/ip/localhost.txt"
                self.localhost = Attack.file_read(location)

        class JsonFuzzing:
            """This implement the values of JSON FUZZING from FUZZDB """

            def __init__(self):
                location = "/web/data/fuzzdb/attack/json/JSON_Fuzzing.txt"
                self.json_fuzzing = Attack.file_read(location)

        class LdapInjection:
            """This implement the values of JSON FUZZING from FUZZDB """

            def __init__(self):
                location = "/web/data/fuzzdb/attack/ldap/ldap-injection.txt"
                self.ldap_injection = Attack.file_read(location)

        class LFI:
            """This implement the values of JSON FUZZING from FUZZDB """

            def __init__(self):
                location = (
                    "/web/data/fuzzdb/attack/lfi/common-ms-httpd-log-locations.txt"
                )
                self.common_ms_httpd_log_locations = Attack.file_read(location)
                location = (
                    "/web/data/fuzzdb/attack/lfi/common-unix-httpd-log-locations.txt"
                )
                self.common_unix_httpd_log_locations = Attack.file_read(location)
                location = "/web/data/fuzzdb/attack/lfi/JHADDIX_LFI.txt"
                self.JHADDIX_LFI = Attack.file_read(location)

        class MimeTypes:
            """This implement the MIME TYPES values from FUZZDB """

            def __init__(self):
                location = "/web/data/fuzzdb/attack/mimetypes/MimeTypes.txt"
                self.mime_types = Attack.file_read(location)

        class NoSqli:
            """This implement the MIME TYPES values from FUZZDB """

            def __init__(self):
                location = "/web/data/fuzzdb/attack/no-sql-injection/mongodb.txt"
                self.mongodb_nosqli = Attack.file_read(location)

            class Extended:
                """This implement the MIME TYPES values from cr0hn
                https://github.com/cr0hn/nosqlinjection_wordlists.git """

                def __init__(self):
                    location = "/extended/nosqlinjection_wordlists/mongodb_nosqli.txt"
                    self.mongodb_nosqli_extented = Attack.file_read(location)

        class OSCommandInjection:
            """This implement the OS Command Injection from FUZZDB """

            def __init__(self):
                location = "/web/data/fuzzdb/attack/os-cmd-execution/command-execution-unix.txt"
                self.command_execution_unix = Attack.file_read(location)

                location = "/web/data/fuzzdb/attack/os-cmd-execution/command-injection-template.txt"
                # Implement a replacement of commands to execute
                self.command_injection_template = Attack.file_read(location)

                location = "/web/data/fuzzdb/attack/os-cmd-execution/Commands-Linux.txt"
                self.commands_Linux = Attack.file_read(location)

                location = "/web/data/fuzzdb/attack/os-cmd-execution/Commands-OSX.txt"
                self.commands_OSX = Attack.file_read(location)

                location = (
                    "/web/data/fuzzdb/attack/os-cmd-execution/Commands-Windows.txt"
                )
                self.command_execution_windows = Attack.file_read(location)

                location = "/web/data/fuzzdb/attack/os-cmd-execution/Commands-WindowsPowershell.txt"
                self.command_execution_windows_powershell = Attack.file_read(location)

                location = "/web/data/fuzzdb/attack/os-cmd-execution/OSCommandInject.Windows.txt"
                self.OSCommandsInjectWindows = Attack.file_read(location)

                location = (
                    "/web/data/fuzzdb/attack/os-cmd-execution/shell-delimiters.txt"
                )
                self.shell_delimiters = Attack.file_read(location)

                location = (
                    "/web/data/fuzzdb/attack/os-cmd-execution/shell-operators.txt"
                )
                self.shell_operators = Attack.file_read(location)

                location = "/web/data/fuzzdb/attack/os-cmd-execution/source-disc-cmd-exec-traversal.txt"
                self.source_disc_cmd_exec_traversal = Attack.file_read(location)

                location = (
                    "/web/data/fuzzdb/attack/os-cmd-execution/useful-commands-unix.txt"
                )
                self.useful_commands_unix = Attack.file_read(location)

                location = "/web/data/fuzzdb/attack/os-cmd-execution/useful-commands-windows.txt"
                self.useful_commands_windows = Attack.file_read(location)

        class OSdirectoryIndexing:
            """This implement the OS Command Injection from FUZZDB """

            def __init__(self):
                location = (
                    "/web/data/fuzzdb/attack/os-dir-indexing/directory-indexing.txt"
                )
                self.directory_indexing = Attack.file_read(location)

        class PathTraversal:
            """This implement the OS Command Injection from FUZZDB """

            def __init__(self):
                location = (
                    "/web/data/fuzzdb/attack/path-traversal/path-traversal-windows.txt"
                )
                self.path_traversal_windows = Attack.file_read(location)

                location = "/web/data/fuzzdb/attack/path-traversal/traversals-8-deep-exotic-encoding.txt"
                # Use Regex to replace {FILE} with your target filename
                self.path_traversal_8_deep_exotic_encoding = Attack.file_read(location)

        class Redirect:
            def __init__(self):
                """This implement the Redirect Injection Template from FUZZDB """
                location = (
                    "/web/data/fuzzdb/attack/redirect/redirect-injection-template.txt"
                )
                self.redirect_injection_template = Attack.file_read(location)

                location = "/web/data/fuzzdb/attack/redirect/redirect-urls-template.txt"
                self.redirect_urls_injection_template = Attack.file_read(location)

        class RFI:
            """This implement the Remote File Inclusion from FUZZDB """

            def __init__(self):
                location = "/web/data/fuzzdb/attack/rfi/rfi.txt"
                self.rfi = Attack.file_read(location)

        class ServerSideInclude:
            """This implement the Server Side Include from FUZZDB """

            def __init__(self):
                location = "/web/data/fuzzdb/attack/server-side-include/server-side-includes-generic.txt"
                self.server_side_includes_generic = Attack.file_read(location)

        class SQLi:
            """This implement the SQLi from FUZZDB """

            class Detect:
                def __init__(self):
                    location = (
                        "/web/data/fuzzdb/attack/sql-injection/detect/Generic_SQLI.txt"
                    )
                    self.Generic_SQLI = Attack.file_read(location)

                    location = (
                        "/web/data/fuzzdb/attack/sql-injection/detect/GenericBlind.txt"
                    )
                    self.GenericBlind = Attack.file_read(location)
                    location = "/web/data/fuzzdb/attack/sql-injection/detect/MSSQL.txt"
                    self.MSSQL = Attack.file_read(location)

                    location = (
                        "/web/data/fuzzdb/attack/sql-injection/detect/MSSQL_blind.txt"
                    )
                    self.MSSQL_blind = Attack.file_read(location)

                    location = "/web/data/fuzzdb/attack/sql-injection/detect/MySQL.txt"
                    self.MySQL = Attack.file_read(location)

                    location = (
                        "/web/data/fuzzdb/attack/sql-injection/detect/MySQL_MSSQL.txt"
                    )
                    self.MySQL_MSSQL = Attack.file_read(location)

                    location = "/web/data/fuzzdb/attack/sql-injection/detect/oracle.txt"
                    self.Oracle = Attack.file_read(location)

                    location = (
                        "/web/data/fuzzdb/attack/sql-injection/detect/xplatform.txt"
                    )
                    self.XPlatform = Attack.file_read(location)

            class Exploit:
                def __init__(self):
                    location = "/web/data/fuzzdb/attack/sql-injection/exploit/db2-enumeration.txt"
                    self.db2_enumeration = Attack.file_read(location)
                    location = "/web/data/fuzzdb/attack/sql-injection/exploit/ms-sql-enumeration.txt"
                    self.ms_sql_enumeration = Attack.file_read(location)

                    location = "/web/data/fuzzdb/attack/sql-injection/exploit/mysql-injection-login-bypass.txt"
                    self.mysql_injection_login_bypass = Attack.file_read(location)

                    location = "/web/data/fuzzdb/attack/sql-injection/exploit/mysql-read-local-files.txt"
                    self.mysql_read_local_files = Attack.file_read(location)

                    location = "/web/data/fuzzdb/attack/sql-injection/exploit/postgres-enumeration.txt"
                    self.postgres_enumeration = Attack.file_read(location)

            class PayloadsSqlBlind:
                def __init__(self):
                    location = "/web/data/fuzzdb/attack/sql-injection/payloads-sql-blind/payloads-sql-blind-MSSQL-INSERT.txt"
                    self.payloads_sql_blind_MSSQL_INSERT = Attack.file_read(location)
                    location = "/web/data/fuzzdb/attack/sql-injection/payloads-sql-blind/payloads-sql-blind-MSSQL-WHERE.txt"
                    self.payloads_sql_blind_MSSQL_WHERE = Attack.file_read(location)

                    location = "/web/data/fuzzdb/attack/sql-injection/payloads-sql-blind/payloads-sql-blind-MySQL-INSERT.txt"
                    self.payloads_sql_blind_MySQL_INSERT = Attack.file_read(location)

                    location = "/web/data/fuzzdb/attack/sql-injection/payloads-sql-blind/payloads-sql-blind-MySQL-ORDER_BY.txt"
                    self.payloads_sql_blind_MySQL_ORDERBY = Attack.file_read(location)

                    location = "/web/data/fuzzdb/attack/sql-injection/payloads-sql-blind/payloads-sql-blind-MySQL-WHERE.txt"
                    self.payloads_sql_blind_MySQL_WHERE = Attack.file_read(location)

        class StringExpansion:
            """This implement the String Expansion values from FUZZDB """

            def __init__(self):
                location = (
                    "/web/data/fuzzdb/attack/string-expansion/shell-expansion.txt"
                )
                self.shell_expansion = Attack.file_read(location)

        class Unicode:
            """This implement the UNICODE values from FUZZDB """

            def __init__(self):
                location = "/web/data/fuzzdb/attack/unicode/corrupted.txt"
                self.corrupted = Attack.file_read(location)
                location = "/web/data/fuzzdb/attack/unicode/emoji.txt"
                self.emoji = Attack.file_read(location)

                location = "/web/data/fuzzdb/attack/unicode/japanese-emoticon.txt"
                self.japanese_emoticon = Attack.file_read(location)

                location = "/web/data/fuzzdb/attack/unicode/naughty-unicode.txt"
                self.naughty_unicode = Attack.file_read(location)

                location = "/web/data/fuzzdb/attack/unicode/regionalindicators.txt"
                self.regionalindicators = Attack.file_read(location)
                location = "/web/data/fuzzdb/attack/unicode/right-to-left.txt"
                self.right_to_left = Attack.file_read(location)

                location = "/web/data/fuzzdb/attack/unicode/specialchars.txt"
                self.specialchars = Attack.file_read(location)

                location = "/web/data/fuzzdb/attack/unicode/two-byte-chars.txt"
                self.two_byte_chars = Attack.file_read(location)

                location = "/web/data/fuzzdb/attack/unicode/upsidedown.txt"
                self.upsidedown = Attack.file_read(location)

        class XML:
            """This implement the XML values from FUZZDB """

            def __init__(self):
                location = "/fuzzdb/attack/xml/xml-attacks.txt"
                self.xml_attacks = Attack.file_read(location)

        class XPATH:
            """This implement the XPATH INJECTIONS values from FUZZDB """

            def __init__(self):
                location = "/web/data/fuzzdb/attack/xpath/xpath-injection.txt"

        class XSS:
            """This implement the XSS INJECTIONS values from FUZZDB """

            def __init__(self):
                location = "/web/data/fuzzdb/attack/xss/all-encodings-of-lt.txt"
                self.all_encodings_of_lt = Attack.file_read(location)

                location = "/web/data/fuzzdb/attack/xss/default-javascript-event-attributes.txt"
                self.default_javascript_event_attirbutes = Attack.file_read(location)

                location = "/web/data/fuzzdb/attack/xss/html-event-attributes.txt"
                self.html_event_attributes = Attack.file_read(location)

                location = (
                    "/web/data/fuzzdb/attack/xss/JHADDIX_XSS_WITH_CONTEXT.doc.txt"
                )
                self.JHADIX_XSS_WITH_CONTEXT = Attack.file_read(location)

                location = "/web/data/fuzzdb/attack/xss/test.xxe"
                self.test_xxe = Attack.file_read(location)

                location = "/web/data/fuzzdb/attack/xss/xss-other.txt"
                self.xss_other = Attack.file_read(location)

                location = "/web/data/fuzzdb/attack/xss/xss-rsnake.txt"
                self.xss_rsnake = Attack.file_read(location)

                location = "/web/data/fuzzdb/attack/xss/xss-uri.txt"
                self.xss_uri = Attack.file_read(location)

                location = "/web/data/fuzzdb/attack/xss/XSSPolyglot.txt"
                self.XSSPolyglot = Attack.file_read(location)

            class Extended:
                """This implement the XSS INJECTIONS EXtended Values MISC """

                # PENDING
                def __init__(self):
                    location = ""
                    self.xss_ext = "pending payloads"

        class XXE:
            """This implement the XXE INJECTIONS MISC """

            # PENDING
            def __init__(self):
                location = ""
                self.xxe = "pending payloads"


class Discovery:
    """ Read the file contents and return the results. Used in the construction
                  of the values for the Discovery Values lists """

    class DNS:
        """ This implements the DNS class of values from fuzzdb """

        def __init__(self):
            location = (
                "/web/data/fuzzdb/discovery/dns/alexaTop1mAXFRcommonSubdomains.txt"
            )
            self.alexaTop1mAXFRcommonSubdomains = Attack.file_read(location)

            location = "/web/data/fuzzdb/discovery/dns/CcTLD.txt"
            self.CCTLD = Attack.file_read(location)

            location = "/web/data/fuzzdb/discovery/dns/dnsmapCommonSubdomains.txt"
            self.dnsmapCommonSubdomains = Attack.file_read(location)

            location = "/web/data/fuzzdb/discovery/dns/gTLD.txt"
            self.gTLD = Attack.file_read(location)

    class PredictableFilepaths:
        """ This implements the Predictable Filepaths class of values from fuzzdb """

        def __init__(self):
            location = "py3wsmfuzz/web/data/fuzzdb/discovery/predictable-filepaths/KitchensinkDirectories.txt"
            self.KitchensinkDirectories = Attack.file_read(location)

            location = "/web/data/fuzzdb/discovery/predictable-filepaths/proxy-conf.txt"
            self.proxy_conf = Attack.file_read(location)

            location = (
                "/web/data/fuzzdb/discovery/predictable-filepaths/Randomfiles.txt"
            )
            self.Randomfiles = Attack.file_read(location)

            location = "/web/data/fuzzdb/discovery/predictable-filepaths/tftp.txt"
            self.tftp = Attack.file_read(location)

            location = (
                "/web/data/fuzzdb/discovery/predictable-filepaths/UnixDotfiles.txt"
            )
            self.UnixDotfiles = Attack.file_read(location)

            location = "py3wsmfuzz/web/data/fuzzdb/discovery/predictable-filepaths/wellknown-rfc5785.txt"
            self.wellknown_rfc5785 = Attack.file_read(location)

        class BackDoors:
            """ This implements BACK DOORS CLASS values from fuzzdb """

            def __init__(self):
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/backdoors/ASP_CommonBackdoors.txt"
                self.ASP_CommonBackDoors = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/backdoors/bot_control_panels.txt"
                self.bot_control_panels = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/backdoors/shells.txt"
                self.shells = Attack.file_read(location)

        class CGI:
            """ This implements the CGI class of values from fuzzdb """

            def __init__(self):
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/cgi/CGI_HTTP_POST.txt"
                self.CGI_HTTP_POST = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/cgi/CGI_HTTP_POST_Windows.txt"
                self.CGI_HTTP_POST_Windows = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/cgi/CGI_Microsoft.txt"
                self.CGI_Microsoft = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/cgi/CGI_XPlatform.txt"
                self.CGI_XPlatform = Attack.file_read(location)

        class CMS:
            """ This implements the CMS class of values from fuzzdb """

            def __init__(self):
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/cms/drupal_plugins.txt"
                self.drupal_plugins = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/cms/drupal_themes.txt"
                self.drupal_themes = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/cms/joomla_plugins.txt"
                self.joomla_plugins = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/cms/joomla_themes.txt"
                self.joomla_themes = Attack.file_read(location)

                location = (
                    "/web/data/fuzzdb/discovery/predictable-filepaths/cms/php-nuke.txt"
                )
                self.php_nuke = Attack.file_read(location)

                location = (
                    "/web/data/fuzzdb/discovery/predictable-filepaths/cms/wordpress.txt"
                )
                self.wordpress = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/cms/wp_common_theme_files.txt"
                self.wp_common_theme_files = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/cms/wp_plugins.txt"
                self.wp_plugins = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/cms/wp_plugins_top225.txt"
                self.wp_plugins_top225 = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/cms/wp_themes.readme"
                self.wp_themes.readme = Attack.file_read(location)

                location = (
                    "/web/data/fuzzdb/discovery/predictable-filepaths/cms/wp_themes.txt"
                )
                self.wp_themes = Attack.file_read(location)

        class FilenameDirnameBruteforce:
            """ This implements the Filename Dirname Bruteforce class from fuzzdb """

            def __init__(self):
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/3CharExtBrute.txt"
                self._3CharExtBrute = Attack.file_read(location)
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/CommonWebExtensions.txt"
                self.CommonWebExtensions = Attack.file_read(location)
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/copy_of.txt"
                self.copy_of = Attack.file_read(location)
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/Extensions.Backup.txt"
                self.ExtensionsBackup = Attack.file_read(location)
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/Extensions.Common.txt"
                self.ExtensionsCommon = Attack.file_read(location)
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/Extensions.Compressed.txt"
                self.ExtensionsCompressed = Attack.file_read(location)
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/WordlistSkipfish.txt"
                self.WordlistSkipfish = Attack.file_read(location)
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/upload_variants.txt"
                self.upload_variants = Attack.file_read(location)
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/test_demo.txt"
                self.test_demo = Attack.file_read(location)
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/spanish.txt"
                self.spanish = Attack.file_read(location)
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-small-words.txt"
                self.raft_small_words = Attack.file_read(location)
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-small-words-lowercase.txt"
                self.raft_small_words_lowercase = Attack.file_read(location)
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-small-files.txt"
                self.raft_small_files = Attack.file_read(location)
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-small-files-lowercase.txt"
                self.raft_small_files_lowercase = Attack.file_read(location)
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-small-extensions.txt"
                self.raft_small_extensions = Attack.file_read(location)
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-small-extensions-lowercase.txt"
                self.raft_small_extentions_lowercase = Attack.file_read(location)
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-small-directories.txt"
                self.raft_small_diectories = Attack.file_read(location)
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-small-directories-lowercase.txt"
                self.raft_small_directories_lowercase = Attack.file_read(location)
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-medium-words.txt"
                self.raft_medium_words = Attack.file_read(location)
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-medium-words-lowercase.txt"
                self.raft_medium_words_lowercase = Attack.file_read(location)
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-medium-files.txt"
                self.raft_medium_files = Attack.file_read(location)
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-medium-files-lowercase.txt"
                self.raft_medium_files_lowercase = Attack.file_read(location)
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-medium-extensions.txt"
                self.raft_medium_extensions = Attack.file_read(location)
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-medium-extensions-lowercase.txt"
                self.raft_medium_lower_lowercase = Attack.file_read(location)
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-medium-directories.txt"
                self.raft_medium_directories = Attack.file_read(location)
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-medium-directories-lowercase.txt"
                self.raft_medium_directories_lowercase = Attack.file_read(location)
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-words.txt"
                self.raft_large_words = Attack.file_read(location)
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-words-lowercase.txt"
                self.raft_large_words_lowercase = Attack.file_read(location)
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-files.txt"
                self.raft_large_files = Attack.file_read(location)
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-files-lowercase.txt"
                self.raft_large_files_lowercase = Attack.file_read(location)
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-extensions.txt"
                self.raft_large_extentions = Attack.file_read(location)
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-extensions-lowercase.txt"
                self.raft_large_extentions_lowercase = Attack.file_read(location)
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-directories.txt"
                self.raft_large_directories = Attack.file_read(location)
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-directories-lowercase.txt"
                self.raft_large_directories_lowercase = Attack.file_read(location)
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/Extensions.Skipfish.txt"
                self.ExtensionSkipfish = Attack.file_read(location)
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/Extensions.Mostcommon.txt"
                self.ExtensionsMostcommon = Attack.file_read(location)

        class LoginFileLocations:
            """ This implements the LoginFileLocations class from fuzzdb """

            def __init__(self):
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/login-file-locations/cfm.txt"
                self.cfm = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/login-file-locations/html.txt"
                self.html = Attack.file_read(location)

                location = "py3wsmfuzz/web/data/fuzzdb/discovery/predictable-filepaths/login-file-locations/jsp.txt"
                self.jsp = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/login-file-locations/Logins.txt"
                self.Logins = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/login-file-locations/php.txt"
                self.php = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/login-file-locations/windows-asp.txt"
                self.windows_asp = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/login-file-locations/windows-aspx.txt"
                self.windows_aspx = Attack.file_read(location)

        class PasswordFileLocations:
            """ This implements the Password LoginFileLocations class from fuzzdb """

            def __init__(self):
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/password-file-locations/Passwords.txt"
                self.Passwords = Attack.file_read(location)

        class PHP:
            """ This implements the PHP class from fuzzdb """

            def __init__(self):
                location = (
                    "/web/data/fuzzdb/discovery/predictable-filepaths/php/PHP.txt"
                )
                self.PHP = Attack.file_read(location)
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/php/PHP_CommonBackdoors.txt"
                self.PHPCommonBackdoors = Attack.file_read(location)

        class WebServersAppServers:
            """ This implements the WebServersAppServer class from fuzzdb """

            def __init__(self):
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/webservers-appservers/Websphere.txt"
                self.Websphere = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/webservers-appservers/Weblogic.txt"
                self.Weblogic = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/webservers-appservers/Vignette.txt"
                self.Vignette = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/webservers-appservers/SuniPlanet.txt"
                self.Suniplanet = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/webservers-appservers/SunAppServerGlassfish.txt"
                self.SunniAppServerGlassfish = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/webservers-appservers/SiteMinder.txt"
                self.SiteMinder = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/webservers-appservers/Sharepoint.txt"
                self.SharePoint = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/webservers-appservers/SAP.txt"
                self.SAP = Attack.file_read(location)
                location = "/web/data/fuzzdb/discovery/predictable-filepaths/webservers-appservers/Ruby_Rails.txt"
                self.Ruby_Rails = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/webservers-appservers/OracleAppServer.txt"
                self.OracleAppServer = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/webservers-appservers/Oracle9i.txt"
                self.Oracle9i = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/webservers-appservers/Netware.txt"
                self.Netware = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/webservers-appservers/LotusNotes.txt"
                self.LotusNotes = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/webservers-appservers/JRun.txt"
                self.JRun = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/webservers-appservers/Joomla_exploitable.txt"
                self.Joomla_exploitable = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/webservers-appservers/JBoss.txt"
                self.JBoss = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/webservers-appservers/JavaServlets_Common.txt"
                self.JavaServlets_Common = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/webservers-appservers/IIS.txt"
                self.IIS = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/webservers-appservers/Hyperion.txt"
                self.Hyperion = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/webservers-appservers/HTTP_POST_Microsoft.txt"
                self.HTTP_POST_Microsoft = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/webservers-appservers/HP_System_Mgmt_Homepage.txt"
                self.HP_System_Mgmt_Homepage = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/webservers-appservers/Frontpage.txt"
                self.Frontpage = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/webservers-appservers/FatwireCMS.txt"
                self.FatwireCMS = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/webservers-appservers/ColdFusion.txt"
                self.ColdFusion = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/webservers-appservers/Apache.txt"
                self.Apache = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/webservers-appservers/ApacheTomcat.txt"
                self.ApacheTomcat = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/webservers-appservers/Apache_Axis.txt"
                self.Apache_Axis = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/webservers-appservers/AdobeXML.txt"
                self.AdobeXML = Attack.file_read(location)

                location = "/web/data/fuzzdb/discovery/predictable-filepaths/webservers-appservers/ADFS.txt"
                self.ADFS = Attack.file_read(location)

    class UserAgent:
        """ This implements the UserAgent class from fuzzdb """

        def __init__(self):
            location = "/web/data/fuzzdb/discovery/UserAgent/UserAgentListCommon.txt"
            self.UserAgentListCommon = Attack.file_read(location)

            location = (
                "py3wsmfuzz/web/data/fuzzdb/discovery/UserAgent/UserAgentListLarge.txt"
            )
            self.UserAgentListLarge = Attack.file_read(location)

            location = "py3wsmfuzz/web/data/fuzzdb/discovery/UserAgent/UserAgents.txt"
            self.UserAgents = Attack.file_read(location)


class Regex:
    """ This implements the Regex class from fuzzdb """

    def __init__(self):
        location = "/web/data/fuzzdb/regex/amazon.txt"
        self.amazon = Attack.file_read(location)

        location = "/web/data/fuzzdb/regex/breakpoint-ignores.txt"
        self.breakpoint_ignores = Attack.file_read(location)

        location = "/web/data/fuzzdb/regex/errors.txt"
        self.errors = Attack.file_read(location)

        location = "/web/data/fuzzdb/regex/nsa-wordlist.txt"
        self.nsa_wordlist = Attack.file_read(location)

        location = "/web/data/fuzzdb/regex/pii.readme.txt"
        self.pii_readme = Attack.file_read(location)

        location = "/web/data/fuzzdb/regex/pii.txt"
        self.pii = Attack.file_read(location)

        location = "/web/data/fuzzdb/regex/sessionid.txt"
        self.sessionid = Attack.file_read(location)


class WebBackdoors:
    """ This implements the WebBackdoors class from fuzzdb """

    class ASP:
        def __init__(self):
            location = "/web/data/fuzzdb/web-backdoors/asp/up.asp"
            self.up = Attack.file_read(location)

            location = "/web/data/fuzzdb/web-backdoors/asp/shell.aspx"
            self.shell_aspx = Attack.file_read(location)

            location = "/web/data/fuzzdb/web-backdoors/asp/shell.asp"
            self.shell_asp = Attack.file_read(location)

            location = "/web/data/fuzzdb/web-backdoors/asp/proxy.asp"
            self.proxy_asp = Attack.file_read(location)

            location = "/web/data/fuzzdb/web-backdoors/asp/ntdaddy.asp"
            self.ntdaddy = Attack.file_read(location)

            location = "/web/data/fuzzdb/web-backdoors/asp/list.txt"
            self.list_txt = Attack.file_read(location)

            location = "/web/data/fuzzdb/web-backdoors/asp/list.asp"
            self.list_asp = Attack.file_read(location)

            location = "/web/data/fuzzdb/web-backdoors/asp/file.asp"
            self.file_asp = Attack.file_read(location)

            location = "/web/data/fuzzdb/web-backdoors/asp/dns.asp"
            self.dns_asp = Attack.file_read(location)

            location = "/web/data/fuzzdb/web-backdoors/asp/cmd.aspx"
            self.cmd_aspx = Attack.file_read(location)

            location = "/web/data/fuzzdb/web-backdoors/asp/cmdasp.aspx"
            self.cmdasp_aspx = Attack.file_read(location)

            location = "/web/data/fuzzdb/web-backdoors/asp/cmdasp.asp"
            self.cmdasp_asp = Attack.file_read(location)

            location = "/web/data/fuzzdb/web-backdoors/asp/cmd-asp-5.1.asp"
            self.cmd_asp_5_1_asp = Attack.file_read(location)

            location = "/web/data/fuzzdb/web-backdoors/asp/cmd.asp"
            self.cmd_asp = Attack.file_read(location)

    class C:
        def __init__(self):
            location = "/web/data/fuzzdb/web-backdoors/c/cmd.c"
            self.up = Attack.file_read(location)

    class CFM:
        def __init__(self):
            location = "/web/data/fuzzdb/web-backdoors/cfm/cfExec.cfm"
            self.cfExec_cfm = Attack.file_read(location)

            location = "/web/data/fuzzdb/web-backdoors/cfm/cfSQL.cfm"
            self.cfSQL_cfm = Attack.file_read(location)

            location = "/web/data/fuzzdb/web-backdoors/cfm/cmd.cfm"
            self.cmd_cfm = Attack.file_read(location)

            location = "/web/data/fuzzdb/web-backdoors/cfm/shell.cfm"
            self.cfSQL_cfm = Attack.file_read(location)

    class ExeNetcat:
        @staticmethod
        def NC():
            """ Execute Netcat """
            netcat = "/web/data/fuzzdb/web-backdoors/exe/nc.exe"
            os.system(netcat)

    class JSP:
        def __init__(self):
            location = "/web/data/fuzzdb/web-backdoors/jsp/browser.jsp"
            self.browser_jsp = Attack.file_read(location)

            location = "/web/data/fuzzdb/web-backdoors/jsp/cmd.jsp"
            self.cmd_jsp = Attack.file_read(location)

            location = "/web/data/fuzzdb/web-backdoors/jsp/cmdjsp.jsp"
            self.cmdjsp_jsp = Attack.file_read(location)

            location = "/web/data/fuzzdb/web-backdoors/jsp/CmdServlet.java"
            self.CmdServlet_java = Attack.file_read(location)

            location = "/web/data/fuzzdb/web-backdoors/jsp/jsp-reverse.jsp"
            self.jsp_reverse_jsp = Attack.file_read(location)

            location = "/web/data/fuzzdb/web-backdoors/jsp/list.jsp"
            self.list_jsp = Attack.file_read(location)

            location = "/web/data/fuzzdb/web-backdoors/jsp/ListServlet.java"
            self.ListServlet_java = Attack.file_read(location)

            location = "/web/data/fuzzdb/web-backdoors/jsp/simple.jsp"
            self.simple_jsp = Attack.file_read(location)

            location = "/web/data/fuzzdb/web-backdoors/jsp/up.jsp"
            self.up_jsp = Attack.file_read(location)

            location = "/web/data/fuzzdb/web-backdoors/jsp/UpServlet.java"
            self.UpServlet_java = Attack.file_read(location)

        def __repr__(self):
            return f"{__name__}{self.__class__.__name__}{self.browser_jsp} {self.CmdServlet_java} {self.ListServlet_java} " \
                   f"{self.cmdjsp_jsp} {self.cmd_jsp} {self.jsp_reverse_jsp} {self.list_jsp} {self.cmd_jsp} {self.up_jsp} " \
                   f"{self.simple_jsp} {self.UpServlet_java}"

        def make_war(self):
            """ Create WAR File  """
            path = Attack.MODPATH + "/web/data/fuzzdb/web-backdoors/jsp/laudanum/"
            try:
                os.system(f"jar -cvf cmd.war {path}warfiles/*")
            except Exception as e:
                print(f"Exception Occurred {e}")
            exit(1)

        class Win32:
            def __init__(self):
                location = "/web/data/fuzzdb/web-backdoors/jsp/win32/cmd_win32.jsp"
                self.cmd_win32_jsp = Attack.file_read(location)
                location = "/fuzzdb/web-backdoors/jsp/win32/up_win32.jsp"
                self.up_win32_jsp = Attack.file_read(location)

    class PHP:
        def __init__(self):
            location = "/web/data/fuzzdb/web-backdoors/php/cmd.php"
            self.cmd_php = Attack.file_read(location)

            location = "/web/data/fuzzdb/web-backdoors/php/up.php"
            self.up_php = Attack.file_read(location)

            location = "/web/data/fuzzdb/web-backdoors/php/tiny.php"
            self.tiny_php = Attack.file_read(location)

            location = "/web/data/fuzzdb/web-backdoors/php/simple-backdoor.php"
            self.simple_backdoor__php = Attack.file_read(location)

            location = "/web/data/fuzzdb/web-backdoors/php/shell.php"
            self.shell_php = Attack.file_read(location)

            location = "/web/data/fuzzdb/web-backdoors/php/proxy.php"
            self.proxy_php = Attack.file_read(location)

            location = "/web/data/fuzzdb/web-backdoors/php/php-reverse-shell.php"
            self.php_reverse_shell_php = Attack.file_read(location)

            location = "/web/data/fuzzdb/web-backdoors/php/php-backdoor.php"
            self.php_backdoor_php = Attack.file_read(location)

            location = "/web/data/fuzzdb/web-backdoors/php/list.php"
            self.list_php = Attack.file_read(location)

            location = "/web/data/fuzzdb/web-backdoors/php/killnc.php"
            self.killnc_php = Attack.file_read(location)

            location = "/web/data/fuzzdb/web-backdoors/php/host.php"
            self.host_php = Attack.file_read(location)

            location = "/web/data/fuzzdb/web-backdoors/php/file.php"
            self.file_php = Attack.file_read(location)

            location = "/web/data/fuzzdb/web-backdoors/php/dns.php"
            self.dns_php = Attack.file_read(location)

    class PlCgi:
        def __init__(self):
            location = "/web/data//fuzzdb/web-backdoors/pl-cgi/cmd.pl"
            self.cmd_pl = Attack.file_read(location)

        def __repr__(self):
            return f"{self.__class__.__name__} {self.cmd_pl!r}"

    class Servelt:
        def __init__(self):
            location = "/web/data/fuzzdb/web-backdoors/servlet/CmdServlet.java"
            self.CmdServlet_java = Attack.file_read(location)
            location = "/web/data/fuzzdb/web-backdoors/servlet/ListServlet.java"
            self.ListServlet_java = Attack.file_read(location)
            location = "/web/data/fuzzdb/web-backdoors/servlet/UpServlet.java"
            self.UpServlet_java = Attack.file_read(location)

        def __repr__(self):
            return f"{self.__class__.__name__} {self.CmdServlet_java} {self.ListServlet_java} {self.UpServlet_java}"

    class SH:
        def __init__(self):
            location = "/web/data/fuzzdb/web-backdoors/sh/cmd.sh"
            self.cmd_sh = Attack.file_read(location)
            location = "/web/data/fuzzdb/web-backdoors/sh/list.sh"
            self.list_sh = Attack.file_read(location)
            location = "/web/data/fuzzdb/web-backdoors/sh/up.sh"
            self.up_sh = Attack.file_read(location)

        def __repr__(self):
            return (
                f"{self.__class__.__name__} {self.cmd_sh} {self.list_sh}  {self.up_sh}"
            )

    class WordPress:
        def __init__(self):
            location = "/web/data/fuzzdb/web-backdoors/wordpress/laudanum.php"
            self.laudanum_php = Attack.file_read(location)

        def __repr__(self):
            return f"{self.__class__.__name__} {self.laudanum_php}"

        class Templates:
            def __init__(self):
                location = (
                    "/web/data/fuzzdb/web-backdoors/wordpress/templates/shell.php"
                )
                self.shell_php = Attack.file_read(location)

                location = (
                    "/web/data/fuzzdb/web-backdoors/wordpress/templates/settings.php"
                )
                self.settings_php = Attack.file_read(location)

                location = (
                    "/web/data/fuzzdb/web-backdoors/wordpress/templates/README.md"
                )
                self.README = Attack.file_read(location)

                location = (
                    "/web/data/fuzzdb/web-backdoors/wordpress/templates/proxy.php"
                )
                self.proxy_php = Attack.file_read(location)

                location = "/web/data/fuzzdb/web-backdoors/wordpress/templates/php-reverse-shell.php"
                self.php_reverse_shell = Attack.file_read(location)

                location = (
                    "/web/data/fuzzdb/web-backdoors/wordpress/templates/killnc.php"
                )
                self.killnc_php = Attack.file_read(location)

                location = (
                    "/web/data/fuzzdb/web-backdoors/wordpress/templates/ipcheck.php"
                )
                self.ipcheck_php = Attack.file_read(location)

                location = "/web/data/fuzzdb/web-backdoors/wordpress/templates/host.php"
                self.host_php = Attack.file_read(location)

                location = "/web/data/fuzzdb/web-backdoors/wordpress/templates/file.php"
                self.file_php = Attack.file_read(location)

                location = "/web/data/fuzzdb/web-backdoors/wordpress/templates/dns.php"
                self.dns_php = Attack.file_read(location)

            def __repr__(self):
                return (
                    f"{self.__class__.__name__} {self.dns_php} {self.file_php} {self.host_php} {self.ipcheck_php} "
                    f"{self.killnc_php} {self.php_reverse_shell} {self.proxy_php} {self.README} {self.settings_php} {self.shell_php}"
                )


class WordListMisc:
    def __init__(self):
        location = "/web/data/fuzzdb/wordlists-misc/accidental_profanity.txt"
        self.accidental_profanity = Attack.file_read(location)

        location = "/web/data/fuzzdb/wordlists-misc/common-http-ports.txt"
        self.common_http_ports = Attack.file_read(location)

        location = "/web/data/fuzzdb/wordlists-misc/numeric.txt"
        self.numeric = Attack.file_read(location)

        location = "/web/data/fuzzdb/wordlists-misc/us_cities.txt"
        self.us_cities = Attack.file_read(location)

        location = "/web/data/fuzzdb/wordlists-misc/wordlist-alphanumeric-case.txt"
        self.wordlist_alphanumeric_case = Attack.file_read(location)

        location = (
            "/web/data/fuzzdb/wordlists-misc/wordlist-common-snmp-community-strings.txt"
        )
        self.wordlist_common_snmp_community_strings = Attack.file_read(location)

        location = "/web/data/fuzzdb/wordlists-misc/wordlist-dna.txt"
        self.wordlist_dna = Attack.file_read(location)

    def __repr__(self):
        return (
            f"{self.__class__.__name__} {self.accidental_profanity} {self.common_http_ports} {self.numeric} {self.us_cities} "
            f"{self.wordlist_alphanumeric_case} {self.wordlist_common_snmp_community_strings} {self.wordlist_dna}"
        )


class WordlistUserPassword:
    def __init__(self):
        location = "/web/data/fuzzdb/wordlists-user-passwd/faithwriters.txt"
        self.faithwriters = Attack.file_read(location)

        location = "/web/data/fuzzdb/wordlists-user-passwd/readme.txt"
        self.readme = Attack.file_read(location)

    def __repr__(self):
        return f"{self.__class__.__name__} {self.faithwriters} {self.readme}"

    class DB2:
        def __init__(self):
            location = "/web/data/fuzzdb/wordlists-user-passwd/db2/db2_default_pass.txt"
            self.db2_default_pass = Attack.file_read(location)

            location = "/web/data/fuzzdb/wordlists-user-passwd/db2/db2_default_user.txt"
            self.db2_default_user = Attack.file_read(location)

            location = (
                "/web/data/fuzzdb/wordlists-user-passwd/db2/db2_default_userpass.txt"
            )
            self.db2_default_userpass = Attack.file_read(location)

        def __repr__(self):
            return f"{self.__class__.__name__} {self.db2_default_pass} {self.db2_default_user} {self.db2_default_userpass}"

    class GenericListpairs:
        def __init__(self):
            location = "pywebfuzz/web/data/fuzzdb/wordlists-user-passwd/generic-listpairs/http_default_pass.txt"
            self.http_default_pass = Attack.file_read(location)

            location = "pywebfuzz/web/data/fuzzdb/wordlists-user-passwd/generic-listpairs/http_default_userpass.txt"
            self.http_default_userpass = Attack.file_read(location)

            location = "pywebfuzz/web/data/fuzzdb/wordlists-user-passwd/generic-listpairs/http_default_users.txt"
            self.http_default_users = Attack.file_read(location)

    class Names:
        def __init__(self):
            location = (
                "pywebfuzz/web/data/fuzzdb/wordlists-user-passwd/names/namelist.txt"
            )
            self.namelist = Attack.file_read(location)

    class Oracle:
        def __init__(self):
            location = "pywebfuzz/web/data/fuzzdb/wordlists-user-passwd/oracle/_hci_oracle_passwords.txt"
            self._hci_oracle_passwords = Attack.file_read(location)

            location = "pywebfuzz/web/data/fuzzdb/wordlists-user-passwd/oracle/oracle_login_password.txt"
            self.oracle_login_password = Attack.file_read(location)

            location = "pywebfuzz/web/data/fuzzdb/wordlists-user-passwd/oracle/oracle_logins.txt"
            self.oracle_logins = Attack.file_read(location)

            location = "pywebfuzz/web/data/fuzzdb/wordlists-user-passwd/oracle/oracle_passwords.txt"
            self.oracle_passwords = Attack.file_read(location)

    class Passwds:
        def __init__(self):
            location = (
                "pywebfuzz/web/data/fuzzdb/wordlists-user-passwd/passwds/john.txt"
            )
            self.john = Attack.file_read(location)

            location = (
                "pywebfuzz/web/data/fuzzdb/wordlists-user-passwd/passwds/phpbb.txt"
            )
            self.phpbb = Attack.file_read(location)

            location = (
                "pywebfuzz/web/data/fuzzdb/wordlists-user-passwd/passwds/twitter.txt"
            )
            self.twitter = Attack.file_read(location)

            location = (
                "pywebfuzz/web/data/fuzzdb/wordlists-user-passwd/passwds/weaksauce.txt"
            )
            self.weaksauce = Attack.file_read(location)

    class Postgres:
        def __init__(self):
            location = "pywebfuzz/web/data/fuzzdb/wordlists-user-passwd/postgres/postgres_default_pass.txt"
            self.postgres_default_pass = Attack.file_read(location)

            location = "pywebfuzz/web/data/fuzzdb/wordlists-user-passwd/postgres/postgres_default_user.txt"
            self.postgres_default_pass = Attack.file_read(location)

            location = "pywebfuzz/web/data/fuzzdb/wordlists-user-passwd/postgres/postgres_default_userpass.txt"
            self.postgres_default_userpass = Attack.file_read(location)

    class Tomcat:
        def __init__(self):
            location = "pywebfuzz/web/data/fuzzdb/wordlists-user-passwd/tomcat/tomcat_mgr_default_pass.txt"
            self.tomcat_mgr_default_pass = Attack.file_read(location)

            location = "pywebfuzz/web/data/fuzzdb/wordlists-user-passwd/tomcat/tomcat_mgr_default_userpass.txt"
            self.tomcat_mgr_default_userpass = Attack.file_read(location)

            location = "pywebfuzz/web/data/fuzzdb/wordlists-user-passwd/tomcat/tomcat_mgr_default_users.txt"
            self.tomcat_mgr_default_users = Attack.file_read(location)

    class UnixOS:
        def __init__(self):
            location = "pywebfuzz/web/data/fuzzdb/wordlists-user-passwd/unix-os/unix_passwords.txt"
            self.unix_passwords = Attack.file_read(location)

            location = (
                "pywebfuzz/web/data/fuzzdb/wordlists-user-passwd/unix-os/unix_users.txt"
            )
            self.unix_users = Attack.file_read(location)

    class FaithWriters:
        def __init__(self):
            location = (
                "pywebfuzz/web/data/fuzzdb/wordlists-user-passwd/faithwriters.txt"
            )
            self.faithwriters = Attack.file_read(location)
