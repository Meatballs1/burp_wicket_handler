# Used as part of Burps Session Handling
# Record a Macro which just gets the page you want to submit (this should give correct wicket:interface in the form)
# Add a new Rule in Options/Sessions
# Set the scope (e.g. Repeater/Scanner/Intruder)
# Add the Macro to the rule and tick 'After running the macro, invoke a Burp extension action handler'
# Select the WicketRequestUpdater
#

from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener
from burp import IScannerListener
from burp import IExtensionStateListener
from burp import ISessionHandlingAction
from java.io import PrintWriter
import re

class BurpExtender(IBurpExtender, ISessionHandlingAction):
    
    #
    # implement IBurpExtender
    #
    
    def	registerExtenderCallbacks(self, callbacks):
        
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # set our extension name
        callbacks.setExtensionName("WicketRequestUpdater")

        callbacks.registerSessionHandlingAction(self)
        
        # obtain our output stream
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

        self._helper = callbacks.getHelpers()

        return

    #
    # implement ISessionHandlingAction
    #

    def processHttpMessage(self):
        return "UpdateInterface"

    #
     # This method is invoked when the session handling action should be
     # executed. This may happen as an action in its own right, or as a
     # sub-action following execution of a macro.
     #
     # @param IHttpRequestResponse currentRequest The base request that is currently being processed.
     # The action can query this object to obtain details about the base
     # request. It can issue additional requests of its own if necessary, and
     # can use the setter methods on this object to update the base request.
     # @param macroItems If the action is invoked following execution of a
     # macro, this parameter contains the result of executing the macro.
     # Otherwise, it is
     # <code>null</code>. Actions can use the details of the macro items to
     # perform custom analysis of the macro to derive values of non-standard
     # session handling tokens, etc.
     #
    def performAction(self, currentRequest, macroItems):      
        if macroItems is None:
            self._stdout.println("No macro defined!")
            return

        if currentRequest is None:
            self._stdout.println("No current request!")
            return

        request_info = self._helper.analyzeRequest(currentRequest.getRequest())
        request_params = request_info.getParameters()
        if request_params is None:
            self._stdout.println("No request params to update")
            return

        wicket_interface = None
        identifier = None
        for p in request_params:
            if p.getName() == "wicket:interface":
                wicket_interface = p
            elif "_hf_0" in p.getName():
                identifier = p

        # Wicket Interface needs updating!
        if wicket_interface is not None:
            for m in macroItems:
                m_response = m.getResponse()
                if m_response is None:
                    self._stderr.println("No Macro Response!")
                    continue
                else:
                    m_response_info = self._helper.analyzeResponse(m_response)
                    m_response_body = self._helper.bytesToString(m_response[m_response_info.getBodyOffset():])
                    re_interface = re.compile(r"(wicket:interface=:)(\d+)(:)")
                    re_identifier = re.compile(r"(\w)+_hf_0")
                    re_interface_sub = re.compile(r"(:)(\d+)(:.+::)")
                    result = re_interface.search(m_response_body)
                    iresult = re_identifier.search(m_response_body)
                    if result is None:
                        self._stderr.println("No interface found in macro response!")
                        continue
                    elif iresult is None:
                        self._stderr.println("No identifier found in macro response!")
                        continue
                    else:
                        # Use \\g<1> so \1## isn't ambiguous!
                        replacement_value = "\\g<1>%s\\3" % result.group(2)
                        wi_value = re_interface_sub.sub(replacement_value, wicket_interface.getValue())
            
                        wicket_interface = self._helper.buildParameter(
                            wicket_interface.getName(),
                            wi_value,
                            wicket_interface.getType())
                        
                        i_name = iresult.group(0)

                        identifier = self._helper.buildParameter(
                            i_name,
                            "",
                            wicket_interface.getType())
                        
                        self._stdout.println("Found wicket interface: %s" % wi_value)
                        self._stdout.println("Found identifier: %s" % i_name)
                           
        if wicket_interface is None or identifier is None:
            self._stderr.println("No new values found in Macro response!")
        else:
            self._stderr.println("Updating request!")
            updated_request = self._helper.updateParameter(currentRequest.getRequest(), wicket_interface)
            updated_request = self._helper.updateParameter(updated_request, identifier)
            #self._stdout.println(self._helper.bytesToString(updated_request))
            currentRequest.setRequest(updated_request)
        

    
      
