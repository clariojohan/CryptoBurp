import base64
from javax.crypto import Cipher
from javax.crypto.spec import IvParameterSpec, GCMParameterSpec, SecretKeySpec

BLOCK_SIZE = 16

from burp import (
    IBurpExtender,
    IHttpListener,
    IContextMenuFactory,
    IContextMenuInvocation,
    IHttpRequestResponse,
)

from javax.swing import (
    JMenuItem,
    JTextArea,
    JOptionPane,
    JFrame,
    JTextField,
    JPanel,
    JLabel,
)


def selectMenu():
    menu = ["AES ECB"]
    result = JOptionPane.showInputDialog(
        None,
        "Select Crypto Algorithm",
        "CryptoBurp",
        JOptionPane.INFORMATION_MESSAGE,
        None,
        menu,
        menu[0],
    )
    return result


def insertKey(key):
    panel = JPanel()
    panel.add(JLabel("Insert your key here:"))
    textfield = JTextField(10)
    panel.add(textfield)
    textfield.setText(
        key
    )  # set default value to previous used key, no redudant input (DONE)

    button = ["Encrypt|Encode|Hash", "Decrypt|Decode", "Cancel"]

    result = JOptionPane.showOptionDialog(
        None,
        panel,
        "Insert Key",
        JOptionPane.YES_NO_CANCEL_OPTION,
        JOptionPane.PLAIN_MESSAGE,
        None,
        button,
        None,
    )

    if textfield.getText() == "":
        JOptionPane.showMessageDialog(None, "Please insert a key")
        return insertKey()
    else:
        if result == JOptionPane.YES_OPTION:
            return textfield.getText(), "Encrypt|Encode|Hash"
        elif result == JOptionPane.NO_OPTION:
            return textfield.getText(), "Decrypt|Decode"
        else:
            return None, "Cancel"


# TO DO : find way to convert ascii array output from selectedText() function to string without using custom ASCIItoStr() function, but instead find and use built-in java function
def ASCIItoStr(asciis):
    string = ""
    for char in asciis:
        string += chr(char)
    return string


def AES_ECB(string, key, data, headers, body, isRequest, mode):
    print("Selected Messages: ", string)
    key = SecretKeySpec(key, "AES")
    cipher = Cipher.getInstance("AES/ECB/PKCS7Padding")

    if mode == "Encrypt|Encode|Hash":
        cipher.init(Cipher.ENCRYPT_MODE, key)
        encrypted = cipher.doFinal(string)
        encrypted = base64.b64encode(encrypted)
        return encrypted
    elif mode == "Decrypt|Decode":
        cipher.init(Cipher.DECRYPT_MODE, key)
        decrypted = cipher.doFinal(base64.b64decode(string))
        decrypted = ASCIItoStr(decrypted)
        return decrypted


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
        callbacks.setExtensionName("CryptoBurp")
        callbacks.registerHttpListener(self)  # register http listener
        callbacks.registerContextMenuFactory(
            self
        )  # register custom item in context menu
        print("CryptoBurp")
        callbacks.issueAlert("CryptoBurp")
        self.key = ""

    def createMenuItems(self, invocation):

        self.data, selectedText = self.selectedText(invocation)
        # TO DO : implement efficient way to grab headers and body to be replaced

        if (
            invocation.getInvocationContext()
            == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST
        ):
            self.isRequest = True
            requestResponse = self.data.getRequest()
            requestResponseData = self._helpers.analyzeRequest(requestResponse)
            self.headers = list(requestResponseData.getHeaders())
            self.body = requestResponse[
                requestResponseData.getBodyOffset() :
            ].tostring()
        elif (
            invocation.getInvocationContext()
            == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE
        ):
            self.isRequest = False
            requestResponse = self.data.getResponse()
            requestResponseData = self._helpers.analyzeResponse(requestResponse)
            self.headers = list(requestResponseData.getHeaders())
            self.body = requestResponse[
                requestResponseData.getBodyOffset() :
            ].tostring()

        self.string = ASCIItoStr(selectedText)

        menuItems = []

        if selectedText:
            menuItems.append(
                JMenuItem(
                    "Select Crypto Algorithm",
                    actionPerformed=lambda event: self.handleMenuSelect(selectMenu()),
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

    def handleMenuSelect(self, menu):
        print("Menu Selected: ", menu)

        # TO DO : implement IV for AES CBC, etc

        if menu == "AES ECB":
            self.key, mode = insertKey(self.key)
            print("Key: ", self.key)
            print("Mode: ", mode)

            if mode == "Cancel":
                return
            else:
                self.replacer = AES_ECB(
                    self.string,
                    self.key,
                    self.data,
                    self.headers,
                    self.body,
                    self.isRequest,
                    mode,
                )
        self.replaceString(
            self.string,
            self.replacer,
            self.data,
            self.headers,
            self.body,
            self.isRequest,
        )
        return


# Footnotes:
# self -> in a class, is a reference to the instance of the class. For example, is you a class named "Person", "self" would be the person object like Person.name equals self.name (inside the class Person itself). So, if we want to access a variable or function/method inside a class, we use self.variable or self.function()
# lambda event: -> is a quick way to create a function in python. For example, we want to create function add(a,b) that returns a+b, we can use lambda a,b: a+b
# To get a return value from a function called by a lambda function -> for example we can use lambda event: self.handleMenuSelect(selectMenu()) -> handleMenuSelect(self, returnValueFromSelectMenu) will get 2 arguments, self and return value from selectMenu() function


# TO DO:
# DONE :
# - [DONE] Update static key to dynamic pop-up input on burp -> use JOptionPane
# - [DONE] Find a way to store the key so that we don't have to re-input the key everytime we want to use the extension -> use JTextField(10).setText(key) -> pass the previous key to the function insertKey() -> self.key initialized in registerExtenderCallbacks() function as empty string
# NOT DONE :
# - [NOT DONE] Add more encryptions, encodings, and hashing algorithms (like cyberchef)
# - [NOT DONE] implement IV for AES CBC, etc
# - [NOT DONE] implement padding selection for AES (PKCS5, PKCS7, etc)
# - [NOT DONE] implement mode selection for AES (ECB, CBC, etc) for more cleaner code and more efficient
# - [NOT DONE] implement error handling for errors like wrong key, wrong padding, wrong mode, or when the output is not a string
# OPTIONAL :
# - find a way to reduce user interaction (clicking, input, etc) -> more efficient

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
# https://portswigger.net/burp/extender/api/
# https://www.tabnine.com/code/java/methods/burp.BurpExtender/exportSave
# https://docs.oracle.com/javase/8/docs/api/javax/swing/JOptionPane.html
# https://docs.oracle.com/javase/8/docs/api/javax/swing/JMenuItem.html
# https://docs.oracle.com/javase/tutorial/uiswing/components/dialog.html
# http://www.java2s.com/Tutorials/Java/Swing/JOptionPane/Customize_JOptionPane_in_Java.htm
# https://stackoverflow.com/questions/13334198/java-custom-buttons-in-showinputdialog
