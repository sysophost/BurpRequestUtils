#!/usr/bin/env python
from burp import IBurpExtender
from burp import IBurpExtenderCallbacks
from burp import IExtensionHelpers
from burp import IContextMenuFactory
from burp import IContextMenuInvocation

from java.util import ArrayList
from javax.swing import JMenuItem
from java.awt import Toolkit
from java.awt.datatransfer import StringSelection
from java.awt.datatransfer import Clipboard

class BurpExtender(IBurpExtender,IContextMenuFactory):

    def	registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.callbacks.setExtensionName("Request Utils")
        self.callbacks.registerContextMenuFactory(self)
        return

    def createMenuItems(self, invocation):
        self.context = invocation
        menu_list = ArrayList()
        menu_list.add(JMenuItem("Copy host only", actionPerformed=self.copy_host))
        menu_list.add(JMenuItem("Copy path only", actionPerformed=self.copy_path))
        menu_list.add(JMenuItem("Copy URL without parameters", actionPerformed=self.copy_url))
        menu_list.add(JMenuItem("Copy parameters", actionPerformed=self.copy_parameters))
        menu_list.add(JMenuItem("Copy headers", actionPerformed=self.copy_headers))
        return menu_list

    def _copy_to_clipboard(self, text):
        toolkit = Toolkit.getDefaultToolkit()
        clipboard = toolkit.getSystemClipboard()
        clipboard.setContents(StringSelection(text), None)

    def _get_request_info(self, IHttpService, httpRequestBytes):
        IRequestInfo = self.helpers.analyzeRequest(IHttpService, httpRequestBytes)
        return IRequestInfo

    def copy_host(self, invocation):
        http_traffic = self.context.getSelectedMessages()
        if http_traffic:
            service = http_traffic[0].getHttpService() #This returns an IHttpService object
            hostname = service.getHost()
            self._copy_to_clipboard(hostname)

    def copy_path(self, invocation):
        http_traffic = self.context.getSelectedMessages()
        if http_traffic:
            httpReqResp = http_traffic[0].getRequest()  #This returns a byte[]
            httpService = http_traffic[0].getHttpService() #This returns a IHttpService object
            reqInfo = self._get_request_info(httpService, httpReqResp)
            url = reqInfo.getUrl().getPath()
            self._copy_to_clipboard(url)

    def copy_url(self, invocation):
        http_traffic = self.context.getSelectedMessages()
        if http_traffic:
            httpReqResp = http_traffic[0].getRequest() #This returns a byte[]
            httpService = http_traffic[0].getHttpService() #This returns a IHttpService object
            reqInfo = self._get_request_info(httpService, httpReqResp)
            url = reqInfo.getUrl()
            urlString = url.toString().split("?", 1)[0]
            self._copy_to_clipboard(urlString)

    def copy_parameters(self, invocation):
        http_traffic = self.context.getSelectedMessages()
        if http_traffic:
            httpReqResp = http_traffic[0].getRequest() #This returns a byte[]
            httpService = http_traffic[0].getHttpService() #This returns a IHttpService object
            reqInfo = self._get_request_info(httpService, httpReqResp)
            params = reqInfo.getParameters() #This returns java.util.List<IParameter>
            print(params)
            self._copy_to_clipboard(params)

    def copy_headers(self, invocation):
        http_traffic = self.context.getSelectedMessages()
        if http_traffic:
            httpReqResp = http_traffic[0].getRequest() #This returns a byte[]
            httpService = http_traffic[0].getHttpService() #This returns a IHttpService object
            reqInfo = self._get_request_info(httpService, httpReqResp)
            headers = reqInfo.getHeaders() #This returns java.util.List<java.lang.String>

            allHeaders = ""
            for h in headers:
                allHeaders += h + "\r\n"

            self._copy_to_clipboard(allHeaders)
