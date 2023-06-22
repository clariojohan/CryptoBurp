import base64
from javax.crypto import Cipher
from javax.crypto.spec import IvParameterSpec, GCMParameterSpec, SecretKeySpec

# TO DO : add more encryptions, encodings, and hashing algorithms (like cyberchef)

BLOCK_SIZE = 16


from burp import (
    IBurpExtender,
    IHttpListener,
    IContextMenuFactory,
    IContextMenuInvocation,
    IHttpRequestResponse,
)

from javax.swing import JMenuItem, JTextArea


# TO DO : find way to convert ascii array output from selectedText() function to string without using custom ASCIItoStr() function, but instead find and use built-in java function
def ASCIItoStr(asciis):
    string = ""
    for char in asciis:
        string += chr(char)
    return string


class BurpExtender(
    IBurpExtender,
    IHttpListener,
    IContextMenuFactory,
    IContextMenuInvocation,
    IHttpRequestResponse,
):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("AES ECB Encryption and Decryption")
        callbacks.registerHttpListener(self)  # register http listener
        callbacks.registerContextMenuFactory(
            self
        )  # register custom item in context menu
        print("AES ECB Encryption and Decryption")
        callbacks.issueAlert("AES ECB Encryption and Decryption")

    def createMenuItems(self, invocation):

        data, selectedText = self.selectedText(invocation)
        # TO DO : implement efficient way to grab headers and body to be replaced

        if (
            invocation.getInvocationContext()
            == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST
        ):
            isRequest = True
            requestResponse = data.getRequest()
            requestResponseData = self._helpers.analyzeRequest(requestResponse)
            headers = list(requestResponseData.getHeaders())
            body = requestResponse[requestResponseData.getBodyOffset() :].tostring()
            print("Request Headers: ", headers)
            print("Request Body: ", body)
        elif (
            invocation.getInvocationContext()
            == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE
        ):
            isRequest = False
            requestResponse = data.getResponse()
            requestResponseData = self._helpers.analyzeResponse(requestResponse)
            headers = list(requestResponseData.getHeaders())
            body = requestResponse[requestResponseData.getBodyOffset() :].tostring()

        string = ASCIItoStr(selectedText)
        key = b"<insert your key here>"
        # TO DO: update static key to dynamic pop-up input on burp

        menuItems = []

        if selectedText:
            menuItems.append(JMenuItem("Encrypt AES ECB"))
            menuItems.append(JMenuItem("Decrypt AES ECB"))

            menuItems[0].addActionListener(
                lambda event: self.encrypt_AES_ECB(
                    string, key, data, headers, body, isRequest
                )
            )
            menuItems[1].addActionListener(
                lambda event: self.decrypt_AES_ECB(
                    string, key, data, headers, body, isRequest
                )
            )

        return menuItems

    def selectedText(self, invocation):
        # reference function from : https://github.com/PortSwigger/json-web-tokens/blob/37baa76170d86e04fe20f511181893823b03eed2/src/app/controllers/ContextMenuController.java#L19

        selection = invocation.getSelectionBounds()

        if selection is None:
            return ""

        ihrr = invocation.getSelectedMessages()[0]
        iContext = invocation.getInvocationContext()

        if (
            iContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST
            or iContext == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST
        ):
            return ihrr, ihrr.getRequest()[selection[0] : selection[1]]

        elif (
            iContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE
            or iContext == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE
        ):
            return ihrr, ihrr.getResponse()[selection[0] : selection[1]]

        else:
            Output.outputError(
                "This context menu case (" + invocation + ") has not been covered yet!"
            )
            return ""

    def replaceString(self, string, replacer, data, headers, body, isRequest):
        if isRequest:
            headers = [x.replace(string, replacer) for x in headers]
            body = body.replace(string, replacer)
            newMessage = self._helpers.buildHttpMessage(headers, body)
            data.setRequest(newMessage)
        else:
            headers = [x.replace(string, replacer) for x in headers]
            body = body.replace(string, replacer)
            newMessage = self._helpers.buildHttpMessage(headers, body)
            data.setResponse(newMessage)

    def encrypt_AES_ECB(self, string, key, data, headers, body, isRequest):
        print("Selected Messages: ", string)

        aesKey = SecretKeySpec(key, "AES")
        cipher = Cipher.getInstance("AES/ECB/PKCS7Padding")
        cipher.init(Cipher.ENCRYPT_MODE, aesKey)
        encrypted = cipher.doFinal(string)
        encrypted = base64.b64encode(encrypted)

        print("Encrypted string: ", encrypted)

        self.replaceString(string, encrypted, data, headers, body, isRequest)

        # return base64.b64encode(encrypted)

    def decrypt_AES_ECB(self, string, key, data, headers, body, isRequest):
        print("Selected Messages: ", string)

        aesKey = SecretKeySpec(key, "AES")
        cipher = Cipher.getInstance("AES/ECB/PKCS7Padding")
        cipher.init(Cipher.DECRYPT_MODE, aesKey)
        decrypted = cipher.doFinal(base64.b64decode(string))

        decrypted = ASCIItoStr(decrypted)

        print("Decrypted string: ", decrypted)

        self.replaceString(string, decrypted, data, headers, body, isRequest)

        # return decrypted


# References:
# https://www.youtube.com/watch?v=zH0_7Ayfxc4&t=219s&ab_channel=EverythingIsHacked
# https://www.youtube.com/playlist?list=PLD3kJNWBcwYElw-RM7taW9TSPPLvsObvd
# https://github.com/PortSwigger/json-web-tokens/blob/37baa76170d86e04fe20f511181893823b03eed2/src/app/controllers/ContextMenuController.java#L19
# https://portswigger.net/burp/extender/api/burp/icontextmenuinvocation.html
# https://portswigger.net/burp/extender/api/burp/icontextmenuinvocation.html#getSelectedMessages--
# https://portswigger.net/burp/extender/api/burp/icontextmenufactory.html
# https://www.tutorialspoint.com/jython/jython_menus.htm
# https://parsiya.net/blog/2019-11-26-swing-in-python-burp-extensions-part-3-tips-and-tricks/#step-1-burpextener-should-inherit-icontextmenufactory
# https://parsiya.net/blog/2019-11-04-swing-in-python-burp-extensions-part-1/
# https://www.tabnine.com/code/java/classes/burp.IHttpRequestResponse
# http://www.java2s.com/example/java/security/aes-decrypt-with-cipher-mode-aesecbnopadding.html
# https://github.com/chrisandoryan/Plainmaker
# https://gist.github.com/nvssks/5c2bc4e9ebcf013ef8cf3282a29fb8d8 -> burp-jython-aes-encrypt.py
# https://cirius.medium.com/writing-your-own-burpsuite-extensions-complete-guide-cb7aba4dbceb
# https://portswigger.net/burp/extender/api/burp/ihttprequestresponse.html
