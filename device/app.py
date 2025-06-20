# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------------
# app.py - Application module
#
# Part of the AlpycaDevice Alpaca skeleton/template device driver
#
# Author:   Robert B. Denny <rdenny@dc3.com> (rbd)
#
# Python Compatibility: Requires Python 3.7 or later
# GitHub: https://github.com/ASCOMInitiative/AlpycaDevice
#
# -----------------------------------------------------------------------------
# MIT License
#
# Copyright (c) 2022-2024 Bob Denny
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# -----------------------------------------------------------------------------
# Edit History:
# 16-Dec-2022   rbd 0.1 Initial edit for Alpaca sample/template
# 20-Dec-2022   rbd 0.1 Correct endpoint URIs
# 21-Dec-2022   rbd 0.1 Refactor for import protection. Add configurtion.
# 22-Dec-2020   rbd 0.1 Start of logging
# 24-Dec-2022   rbd 0.1 Logging
# 25-Dec-2022   rbd 0.1 Add milliseconds to logger time stamp
# 27-Dec-2022   rbd 0.1 Post-processing logging of request only if not 200 OK
#               MIT License and module header. No multicast on device duh.
# 28-Dec-2022   rbd 0.1 Rename conf.py to config.py to avoid conflict with sphinx
# 30-Dec-2022   rbd 0.1 Device number in /setup routing template. Last chance
#               exception handler, Falcon responder uncaught exeption handler.
# 01-Jan-2023   rbd 0.1 Docstring docs
# 13-Jan-2023   rbd 0.1 More docstring docs. Fix LoggingWSGIRequestHandler,
#               log.logger needs explicit setting in main()
# 23-May-2023   rbd 0.2 GitHub Issue #3 https://github.com/BobDenny/AlpycaDevice/issues/3
#               Corect routing device number capture spelling.
# 23-May-2023   rbd 0.2 Refactoring for  multiple ASCOM device type support
#               GitHub issue #1
# 13-Sep-2024   rbd 1.0 Add support for enum classes within the responder modules
#               GitHub issue #12
# 03-Jan-2025   rbd 1.0.1 Clarify devices vs device types at import site. Comment only,
#               no logic changes.
# 20-May-2025   rbd 1.0.3 Issue #19. Allow switching between IPv4 and IPv6 in config.
# 19-Jun-2025   rbd 1.0.3 Thanks to ASCOM Help member Reid Smythe for the solution. Force
#               the wsgiref.simple_server to run in HTTP/1.1. See this discussion:
#               https://ascomtalk.groups.io/g/Developer/topic/alpyca_and_skysafari_http_1_0/113683962
#
import sys
import traceback
import inspect
import socket
from wsgiref.simple_server import make_server, ServerHandler, WSGIServer, WSGIRequestHandler
from enum import IntEnum

# -- isort wants the above line to be blank --
# Controller classes (for routing)
import discovery
import exceptions
from falcon import Request, Response, App, HTTPInternalServerError
# PyLance chokes on management but it is OK
import management
import setup
import log
from config import Config
from discovery import DiscoveryResponder
from shr import set_shr_logger

##############################
# FOR EACH ASCOM DEVICE TYPE #
##############################
import rotator

#--------------
API_VERSION = 1
#--------------

class LoggingWSGIRequestHandler(WSGIRequestHandler):
    """
        Subclass of  WSGIRequestHandler allowing us to control WSGI server's logging
        and to force the simpel server to use HTTP/1.1. Despite many bits of advice on
        the internet and AI, setting protocol_version = 'HTTP/1.1' has no effect. This
        just hijacks the ServerHandler's handle() method, setting its internal version
        string to HTTP/1.1.
    """
    def handle(self):
        # ServerHandler.http_version = 'HTTP/1.1'
        # super().handle()
        # Copy the parent method but override ServerHandler
        self.raw_requestline = self.rfile.readline(65537)
        if len(self.raw_requestline) > 65536:
            self.requestline = ''
            self.request_version = ''
            self.command = ''
            self.send_error(414)
            return

        if not self.parse_request():
            return

        handler = ServerHandler(
            self.rfile, self.wfile, self.get_stderr(), self.get_environ(),
            multithread=False,
        )
        handler.http_version = "1.1"  # Override here
        handler.request_handler = self
        handler.run(self.server.get_app())

    def log_message(self, format: str, *args):
        """Log a message from within the Python **wsgiref** simple server

        Logging elsewhere logs the incoming request *before*
        processing in the responder, making it easier to read
        the overall log. The wsgi server calls this function
        at the end of processing. Normally the request would not
        need to be logged again. However, in order to assure
        logging of responses with HTTP status other than
        200 OK, we log the request again here.

        For more info see
        `this article <https://stackoverflow.com/questions/31433682/control-wsgiref-simple-server-log>`_

        Args:
            format  (str):   Unused, old-style format (see notes)
            args[0] (str):   HTTP Method and URI ("request")
            args[1] (str):   HTTP response status code
            args[2] (str):   HTTP response content-length


        Notes:
            * Logs using :py:mod:`log`, our rotating file logger ,
              rather than using stdout.
            * The **format** argument is an old C-style format for
              for producing NCSA Commmon Log Format web server logging.

        """

        ##TODO## If I enable this, the server occasionally fails to respond
        ##TODO## on non-200s, per Wireshark. So crazy!
        #if args[1] != '200':  # Log this only on non-200 responses
        #    log.logger.info(f'{self.client_address[0]} <- {format%args}')

#-----------------------
# Magic routing function
# ----------------------
def init_routes(app: App, devname: str, module):
    """Initialize Falcon routing from URI to responser classses

    Inspects a module and finds all classes, assuming they are Falcon
    responder classes, and calls Falcon to route the corresponding
    Alpaca URI to each responder. This is done by creating the
    URI template from the responder class name.

    Note that it is sufficient to create the controller instance
    directly from the type returned by inspect.getmembers() since
    the instance is saved within Falcon as its resource controller.
    The responder methods are called with an additional 'devno'
    parameter, containing the device number from the URI. Reject
    negative device numbers.

    Args:
        app (App): The instance of the Falcon processor app
        devname (str): The name of the device (e.g. 'rotator")
        module (module): Module object containing responder classes

    Notes:
        * The call to app.add_route() creates the single instance of the
          router class right in the call, as the second parameter.
        * The device number is extracted from the URI by using an
          **int** placeholder in the URI template, and also using
          a format converter to assure that the number is not
          negative. If it is, Falcon will send back an HTTP
          ``400 Bad Request``.

    """

    memlist = inspect.getmembers(module, inspect.isclass)
    for cname,ctype in memlist:
        # Only classes *defined* in the module and not the enum classes
        if ctype.__module__ == module.__name__ and not issubclass(ctype, IntEnum):
            app.add_route(f'/api/v{API_VERSION}/{devname}/{{devnum:int(min=0)}}/{cname.lower()}', ctype())  # type() creates instance!


def custom_excepthook(exc_type, exc_value, exc_traceback):
    """Last-chance exception handler

    Caution:
        Hook this as last-chance only after the config info
        has been initiized and the logger is set up!

    Assures that any unhandled exceptions are logged to our logfile.
    Should "never" be called since unhandled exceptions are
    theoretically caught in falcon. Well it's here so the
    exception has a chance of being logged to our file. It's
    used by :py:func:`~app.falcon_uncaught_exception_handler` to
    make sure exception info is logged instead of going to
    stdout.

    Args:
        exc_type (_type_): _description_
        exc_value (_type_): _description_
        exc_traceback (_type_): _description_

    Notes:
        * See the Python docs for `sys.excepthook() <https://docs.python.org/3/library/sys.html#sys.excepthook>`_
        * See `This StackOverflow article <https://stackoverflow.com/a/58593345/159508>`_
        * A config option provides for a full traceback to be logged.

    """
    # Do not print exception when user cancels the program
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return

    log.logger.error(f'An uncaught {exc_type.__name__} exception occurred:')
    log.logger.error(exc_value)

    if Config.verbose_driver_exceptions and exc_traceback:
        format_exception = traceback.format_tb(exc_traceback)
        for line in format_exception:
            log.logger.error(repr(line))


def falcon_uncaught_exception_handler(req: Request, resp: Response, ex: BaseException, params):
    """Handle Uncaught Exceptions while in a Falcon Responder

        This catches unhandled exceptions within the Falcon responder,
        logging the info to our log file instead of it being lost to
        stdout. Then it logs and responds with a 500 Internal Server Error.

    """
    exc = sys.exc_info()
    custom_excepthook(exc[0], exc[1], exc[2])
    raise HTTPInternalServerError('Internal Server Error', 'Alpaca endpoint responder failed. See logfile.')

# ===========
# APP STARTUP
# ===========
def main():
    """ Application startup"""

    logger = log.init_logging()
    # Share this logger throughout
    log.logger = logger
    exceptions.logger = logger
    rotator.start_rot_device(logger)
    discovery.logger = logger
    set_shr_logger(logger)

    #########################
    # FOR EACH ASCOM DEVICE #
    #########################
    rotator.logger = logger

    # -----------------------------
    # Last-Chance Exception Handler
    # -----------------------------
    sys.excepthook = custom_excepthook

    # ---------
    # DISCOVERY
    # ---------
    _DSC = DiscoveryResponder(Config.ip_address, Config.port)

    # ----------------------------------
    # MAIN HTTP/REST API ENGINE (FALCON)
    # ----------------------------------
    # falcon.App instances are callable WSGI apps
    falc_app = App()
    #
    # Initialize routes for each endpoint the magic way
    #
    #########################
    # FOR EACH ASCOM DEVICE #
    #########################
    init_routes(falc_app, 'rotator', rotator)
    #
    # Initialize routes for Alpaca support endpoints
    falc_app.add_route('/management/apiversions', management.apiversions())
    falc_app.add_route(f'/management/v{API_VERSION}/description', management.description())
    falc_app.add_route(f'/management/v{API_VERSION}/configureddevices', management.configureddevices())
    falc_app.add_route('/setup', setup.svrsetup())
    falc_app.add_route(f'/setup/v{API_VERSION}/rotator/{{devnum}}/setup', setup.devsetup())

    #
    # Install the unhandled exception processor. See above,
    #
    falc_app.add_error_handler(Exception, falcon_uncaught_exception_handler)

    # ------------------
    # SERVER APPLICATION
    # ------------------
    # Using the lightweight built-in Python wsgi.simple_server
    #
    # The following should allow both IPv4 and IPv6 to be served. But it does
    # not. See comments below. TODO THIS CLASS UNUSED
    #
    class DualStackServer(WSGIServer):
        def __init__(self, server_address, RequestHandlerClass): #server_address is tuple host,
            self.address_family = socket.AF_INET6   # With "::" should allow mapped IPV4 as well
            super().__init__(server_address, RequestHandlerClass)
            # Fails InvalidArgument though  supposedly supported on Windows 7/8/10/11
            # https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ipv6-socket-options
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    #
    # This is an IPv6-only server class
    #
    class IPv6Server(WSGIServer):
        def __init__(self, server_address, RequestHandlerClass): #server_address is tuple host,
            self.address_family = socket.AF_INET6
            super().__init__(server_address, RequestHandlerClass)
    #
    # This serves only IPV4
    #
    class IPv4Server(WSGIServer):
        def __init__(self, server_address, RequestHandlerClass): #server_address is tuple host,
            self.address_family = socket.AF_INET
            super().__init__(server_address, RequestHandlerClass)
    #
    # Server address family per the configuration
    #
    if Config.addr_family == 'ipv6':
        server_class = IPv6Server
    else:
        server_class = IPv4Server
    #
    # Startup the HTTP engine with Falcon on top.
    #
    httpd = make_server(Config.ip_address, Config.port, falc_app,
                server_class=server_class, handler_class=LoggingWSGIRequestHandler)
    LoggingWSGIRequestHandler.protocol_version = 'HTTP/1.1'
    with httpd:
        logger.info(f'==STARTUP== Serving {Config.addr_family} on {Config.ip_address}:{Config.port}. Time stamps are UTC.')
        # Serve until process is killed
        httpd.serve_forever()

# ========================
if __name__ == '__main__':
    main()
# ========================
