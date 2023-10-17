import frappe
frappe.init(site="dev.erpgulf.com")
frappe.connect()
from subprocess import call
import subprocess
import requests
import json
import base64
import sys
import OpenSSL
import chilkat2
from lxml import etree
import re


def file_loading_normal(signedXmlFilePath):
    
    with open(signedXmlFilePath, "r") as file:
            xml = file.read().lstrip()
            base64_encoded = base64.b64encode(xml.encode("utf-8"))
            print(base64_encoded)
            
def file_loading_chilkat(signedXmlFilePath):
        bd = chilkat2.BinData()
        success = bd.LoadFile(signedXmlFilePath)
        xml = bd.GetString("utf-8")
        xml = xml.lstrip()
        base64_encoded = base64.b64encode(xml.encode("utf-8"))
        print(base64_encoded)

signedXmlFilePath = "/opt/bench3/frappe-bench/sites/signedXML_withQR.xml"
# signedXmlFilePath = "/opt/oxy/frappe-bench/sites/signedXML_withQR.xml"
file_loading_chilkat(signedXmlFilePath)
# file_loading_normal(signedXmlFilePath)

