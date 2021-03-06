#!/usr/bin/env python
from burp import IBurpExtender
from burp import IBurpExtenderCallbacks
from burp import IExtensionHelpers
from burp import IContextMenuFactory
from burp import IContextMenuInvocation

from java.util import ArrayList
from javax.swing import JMenuItem
from javax.swing import JMenu
from java.awt import Toolkit
from java.awt.datatransfer import StringSelection
from java.awt.datatransfer import Clipboard


class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.callbacks.setExtensionName("Request Utils")
        self.callbacks.registerContextMenuFactory(self)
        return

    def createMenuItems(self, invocation):
        self.context = invocation

        subMenu = JMenu("Copy Things")
        subMenu.add(JMenuItem("Copy host only", actionPerformed=self.copy_host))
        subMenu.add(JMenuItem("Copy path only", actionPerformed=self.copy_path))
        subMenu.add(JMenuItem("Copy URL without parameters", actionPerformed=self.copy_url))
        subMenu.add(JMenuItem("Copy query parameters", actionPerformed=self.copy_parameters))
        subMenu.add(JMenuItem("Copy body parameters", actionPerformed=self.copy_parameters))
        subMenu.add(JMenuItem("Copy cookies", actionPerformed=self.copy_parameters))
        subMenu.add(JMenuItem("Copy headers", actionPerformed=self.copy_headers))

        menu_list = ArrayList()
        menu_list.add(subMenu)
        return menu_list

    def _copy_to_clipboard(self, text):
        toolkit = Toolkit.getDefaultToolkit()
        clipboard = toolkit.getSystemClipboard()
        clipboard.setContents(StringSelection(text), None)

    def _get_request_info(self, IHttpService, httpRequestBytes):
        IRequestInfo = self.helpers.analyzeRequest(IHttpService, httpRequestBytes)
        return IRequestInfo

    def _get_response_info(self, httpResponseBytes):
        IResponseInfo = self.helpers.analyzeResponse(httpResponseBytes)
        return IResponseInfo

    def _is_request(self):
        # consts taken from https://portswigger.net/burp/extender/api/constant-values.html#burp.IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST 
        if self.context.getInvocationContext() in [0, 2]:
            return True
        else: 
            return False

    def _strip_common_ports(self, url):
        url = url.replace(':80/', '/')  # need the trailing slash here to prevent :8080 being substringed to 80
        url = url.replace(':443/', '/')
        return url

    def copy_host(self, invocation):
        http_traffic = self.context.getSelectedMessages()
        selected_hosts = []
        for http_request in http_traffic:
            service = http_request.getHttpService()  # This returns an IHttpService object
            hostname = service.getHost()

            if hostname not in selected_hosts:
                selected_hosts.append(hostname)

        selected_hosts.sort()
        all_hosts = ('\n'.join(selected_hosts))
        self._copy_to_clipboard(all_hosts)

    def copy_path(self, invocation):
        http_traffic = self.context.getSelectedMessages()
        selected_urls = []

        for http_request in http_traffic:
            httpReqResp = http_request.getRequest()  # This returns a byte[]
            httpService = http_request.getHttpService()  # This returns a IHttpService object
            reqInfo = self._get_request_info(httpService, httpReqResp)
            url = reqInfo.getUrl().getPath()

            if url not in selected_urls:
                selected_urls.append(url)

        selected_urls.sort()
        all_urls = ('\n'.join(selected_urls))
        self._copy_to_clipboard(all_urls)

    def copy_url(self, invocation):
        http_traffic = self.context.getSelectedMessages()
        selected_urls = []
        for http_request in http_traffic:
            httpReqResp = http_request.getRequest()  # This returns a byte[]
            httpService = http_request.getHttpService()  # This returns a IHttpService object
            reqInfo = self._get_request_info(httpService, httpReqResp)
            url = reqInfo.getUrl()
            urlString = str(url).split("?", 1)[0]

            urlString = self._strip_common_ports(urlString)

            if urlString not in selected_urls:
                selected_urls.append(urlString)

        selected_urls.sort()
        all_urls = ('\n'.join(selected_urls))
        self._copy_to_clipboard(all_urls)

    def copy_parameters(self, invocation):
        http_traffic = self.context.getSelectedMessages()
        menu_switcher = {
            "Copy query parameters": 0,
            "Copy body parameters": 1,
            "Copy cookies": 2
        }

        param_type = menu_switcher.get(invocation.getSource().text)
        selected_params = []
        for http_request in http_traffic:
            if self._is_request():
                httpReqResp = http_request.getRequest()  # This returns a byte[]
                httpService = http_request.getHttpService()  # This returns a IHttpService object
                reqInfo = self._get_request_info(httpService, httpReqResp)
                params = reqInfo.getParameters()  # This returns java.util.List<IParameter>

                for param in params:
                    n = param.getName()
                    v = param.getValue()
                    t = param.getType()  # 0 = query param, 1 = body param, 2 = cookie

                    if t == param_type:
                        arrayItem = '{0}={1}'.format(n, v)
                        if arrayItem not in selected_params:
                            selected_params.append(arrayItem)
            else:
                httpReqResp = http_request.getResponse()  # This returns a byte[]
                respInfo = self._get_response_info(httpReqResp)
                cookies = respInfo.getCookies()  # This returns java.util.List<ICookie>

                for cookie in cookies:
                    n = cookie.getName()
                    v = cookie.getValue()

                    arrayItem = '{0}={1}'.format(n, v)
                    if arrayItem not in selected_params:
                        selected_params.append(arrayItem)

            selected_params.sort()
            all_params = ('\n'.join(selected_params))
            self._copy_to_clipboard(all_params)

    def copy_headers(self, invocation):
        http_traffic = self.context.getSelectedMessages()
        selected_headers = []
        for http_request in http_traffic:
            if self._is_request():
                httpReqResp = http_request.getRequest()  # This returns a byte[]
                httpService = http_request.getHttpService()  # This returns a IHttpService object
                reqInfo = self._get_request_info(httpService, httpReqResp)
                headers = reqInfo.getHeaders()  # This returns java.util.List<java.lang.String>
            else:
                httpReqResp = http_request.getResponse()  # This returns a byte[]
                respInfo = self._get_response_info(httpReqResp)
                headers = respInfo.getHeaders()  # This returns java.util.List<java.lang.String>

            for header in headers:
                selected_headers.append(header)

            selected_headers.append('')  # add extra empty header to break up requests

            all_headers = ('\n'.join(selected_headers))
            self._copy_to_clipboard(all_headers)
