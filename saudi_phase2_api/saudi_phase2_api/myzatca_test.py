import frappe
frappe.init(site="husna.erpgulf.com")
frappe.connect()
from subprocess import call
import subprocess
import requests
import json
import base64
import qrcode
import sys
import OpenSSL
import chilkat2
from lxml import etree
import re
def send_invoice_for_clearance_chilkat(invoiceHash, uuid, authorization, secret, signedXmlFilePath ):
        # Sending invoice for clearance through chilkat library - Farook
        bd = chilkat2.BinData()
        success = bd.LoadFile(signedXmlFilePath)
        xml = bd.GetString("utf-8")
        xml = xml.lstrip()
        base64_encoded = base64.b64encode(xml.encode("utf-8"))
        print(base64_encoded)
        
        json = chilkat2.JsonObject()
        json.UpdateString("summary","Standard Invoice")
        json.UpdateString("value.invoiceHash",invoiceHash)
        json.UpdateString("value.uuid",cbc_UUID)
        json.UpdateString("value.invoice",base64_encoded)

        http = chilkat2.Http()
        http.BasicAuth = True
        http.Login = "husna@htsqatar.com"
        http.Password = "Husna@1999cd"
        http.headers.Add("Accept-Language","en")
        # resp is a CkHttpResponse
        resp = http.PostJson3("https://gw-fatoora.zatca.gov.sa/e-invoicing/developer-portal/compliance/invoices","application/json",json)
        if (http.LastMethodSuccess == False):
            print(http.LastErrorText)
            sys.exit()

        # Check the response status code.  A 200 or 202 indicates success..
        statusCode = resp.StatusCode
        # print("Response status code = " + str(statusCode))

        # Examine the response, which is JSON.
        jsonResp = chilkat2.JsonObject()
        resp.GetBodyJson(jsonResp)
        jsonResp.EmitCompact = False
        print("JSON Response:")
        # print(jsonResp.Emit())


def send_invoice_for_clearance_normal():
        
        # Sending invoice for clearance through normal python library - Farook
        # sys.exit()
        invoiceHash = get_InvoiceHash()
        # print(invoiceHash)
        signedXmlFilePath="/opt/oxy/frappe-bench/apps/saudi_phase2_api/saudi_phase2_api/saudi_phase2_api/test_xml_formatter.xml"
        # signedXmlFilePath = "/opt/oxy/frappe-bench/sites/signedXML_withQR.xml"
        print("signedXmlFilePath:   " + signedXmlFilePath)
        token,secret = create_security_token_from_csr()
        uuid =get_UUID()
        with open(signedXmlFilePath, "r") as file:
            xml = file.read().lstrip()
            base64_encoded = base64.b64encode(xml.encode("utf-8"))
            # print(base64_encoded)
            base64_decoded = base64_encoded.decode("utf-8")
            # print(base64_decoded)
            print(xml)
        url = "https://gw-fatoora.zatca.gov.sa/e-invoicing/developer-portal/compliance/invoices"

        payload = json.dumps({
        "invoiceHash": invoiceHash,
        "uuid": uuid,
        "invoice": base64_decoded
        })
        # sys.exit()
        # print(authorization)
        headers = { 
            'accept': 'application/json',
            'Accept-Language': 'en',
            'Accept-Version': 'V2',
            # 'Authorization': 'Basic ' + authorization,
            'Authorization': "Basic VFVsSlJERnFRME5CTTNsblFYZEpRa0ZuU1ZSaWQwRkJaVFJUYUhOMmVXNDNNREo1VUhkQlFrRkJRamRvUkVGTFFtZG5jV2hyYWs5UVVWRkVRV3BDYWsxU1ZYZEZkMWxMUTFwSmJXbGFVSGxNUjFGQ1IxSlpSbUpIT1dwWlYzZDRSWHBCVWtKbmIwcHJhV0ZLYXk5SmMxcEJSVnBHWjA1dVlqTlplRVo2UVZaQ1oyOUthMmxoU21zdlNYTmFRVVZhUm1ka2JHVklVbTVaV0hBd1RWSjNkMGRuV1VSV1VWRkVSWGhPVlZVeGNFWlRWVFZYVkRCc1JGSlRNVlJrVjBwRVVWTXdlRTFDTkZoRVZFbDVUVVJaZUUxNlJURk5la1V3VG14dldFUlVTVEJOUkZsNFRXcEZNVTE2UlRCT2JHOTNVMVJGVEUxQmEwZEJNVlZGUW1oTlExVXdSWGhFYWtGTlFtZE9Wa0pCYjFSQ1YwWnVZVmQ0YkUxU1dYZEdRVmxFVmxGUlRFVjNNVzlaV0d4b1NVaHNhRm95YUhSaU0xWjVUVkpKZDBWQldVUldVVkZFUlhkcmVFMXFZM1ZOUXpSM1RHcEZkMVpxUVZGQ1oyTnhhR3RxVDFCUlNVSkNaMVZ5WjFGUlFVTm5Ua05CUVZSVVFVczViSEpVVm10dk9YSnJjVFphV1dOak9VaEVVbHBRTkdJNVV6UjZRVFJMYlRkWldFb3JjMjVVVm1oTWEzcFZNRWh6YlZOWU9WVnVPR3BFYUZKVVQwaEVTMkZtZERoREwzVjFWVms1TXpSMmRVMU9ielJKUTB0cVEwTkJhVmwzWjFselIwRXhWV1JGVVZOQ1ozcERRbWRMVWl0TlNIZDRTRlJCWWtKblRsWkNRVkZOUmtSRmRHRkhSalZaV0hkNVRGUkplazVJZDNwTVZFVjRUV3BOZWsxU09IZElVVmxMUTFwSmJXbGFVSGxNUjFGQ1FWRjNVRTE2VFhoTlZGbDVUMFJaTlU1RVFYZE5SRUY2VFZFd2QwTjNXVVJXVVZGTlJFRlJlRTFVUVhkTlVrVjNSSGRaUkZaUlVXRkVRV2hoV1ZoU2FsbFRRWGhOYWtWWlRVSlpSMEV4VlVWRWQzZFFVbTA1ZGxwRFFrTmtXRTU2WVZjMWJHTXpUWHBOUWpCSFFURlZaRVJuVVZkQ1FsTm5iVWxYUkRaaVVHWmlZa3RyYlZSM1QwcFNXSFpKWWtnNVNHcEJaa0puVGxaSVUwMUZSMFJCVjJkQ1VqSlpTWG8zUW5GRGMxb3hZekZ1WXl0aGNrdGpjbTFVVnpGTWVrSlBRbWRPVmtoU09FVlNla0pHVFVWUFoxRmhRUzlvYWpGdlpFaFNkMDlwT0haa1NFNHdXVE5LYzB4dWNHaGtSMDVvVEcxa2RtUnBOWHBaVXpsRVdsaEtNRkpYTlhsaU1uaHpUREZTVkZkclZrcFViRnBRVTFWT1JreFdUakZaYTA1Q1RGUkZkVmt6U25OTlNVZDBRbWRuY2tKblJVWkNVV05DUVZGVFFtOUVRMEp1VkVKMVFtZG5ja0puUlVaQ1VXTjNRVmxhYVdGSVVqQmpSRzkyVEROU2VtUkhUbmxpUXpVMldWaFNhbGxUTlc1aU0xbDFZekpGZGxFeVZubGtSVloxWTIwNWMySkRPVlZWTVhCR1lWYzFNbUl5YkdwYVZrNUVVVlJGZFZwWWFEQmFNa1kyWkVNMWJtSXpXWFZpUnpscVdWZDRabFpHVG1GU1ZXeFBWbXM1U2xFd1ZYUlZNMVpwVVRCRmRFMVRaM2hMVXpWcVkyNVJkMHQzV1VsTGQxbENRbEZWU0UxQlIwZElNbWd3WkVoQk5reDVPVEJqTTFKcVkyMTNkV1Z0UmpCWk1rVjFXakk1TWt4dVRtaE1NamxxWXpOQmQwUm5XVVJXVWpCUVFWRklMMEpCVVVSQloyVkJUVUl3UjBFeFZXUktVVkZYVFVKUlIwTkRjMGRCVVZWR1FuZE5RMEpuWjNKQ1owVkdRbEZqUkVGNlFXNUNaMnR5UW1kRlJVRlpTVE5HVVc5RlIycEJXVTFCYjBkRFEzTkhRVkZWUmtKM1RVTk5RVzlIUTBOelIwRlJWVVpDZDAxRVRVRnZSME5EY1VkVFRUUTVRa0ZOUTBFd1owRk5SVlZEU1ZGRVQxQXdaakJFY21oblpVUlVjbFpNZEVwMU9HeFhhelJJU25SbFkyWTFabVpsVWt4blpVUTRZMlZWWjBsblpFSkNUakl4U1RNM2FYTk5PVlZ0VTFGbE9IaFNjRWh1ZDA5NFNXYzNkMDR6V1RKMlZIQnpVR2hhU1QwPTpFcGo2OUdoOFRNTXpZZktsdEx2MW9tWktyaWUwc1A2TEF2YW1iUUZIVGd3PQ==",
            'Content-Type': 'application/json'
        }
        # sys.exit()
        try:
            response = requests.request("POST", url, headers=headers, data=payload)
            # print(response.text)
        except Exception as e:
            
            print(str(e)) 
            sys.exit()
        print(response.text)

def get_signed_xml_invoice_for_clearance():
        #Creating and returning sbDigestValue, xmlSigned, signedXmlFilePath - Farook
        
        signedXmlFilePath = "/opt/oxy/frappe-bench/sites/signedXml.xml"
        # signedXmlFilePath = "/opt/oxy/frappe-bench/sites/signedXML_withQR.xml"
        xmlSigned = chilkat2.Xml()
        success = xmlSigned.LoadXmlFile(signedXmlFilePath)
        if (success == False):
            print(xmlSigned.LastErrorText)
            sys.exit()
        else:
            print("success 120")
        sbDigestValue = chilkat2.StringBuilder()
        success = xmlSigned.GetChildContentSb("ext:UBLExtensions|ext:UBLExtension|ext:ExtensionContent|sig:UBLDocumentSignatures|sac:SignatureInformation|ds:Signature|ds:SignedInfo|ds:Reference[0]|ds:DigestValue",sbDigestValue)
        if (success == False):
            print("Failed to get DigestValue from signed XML.")
            sys.exit()
        # print("DigestValue = " + sbDigestValue.GetAsString())
        return sbDigestValue, xmlSigned, signedXmlFilePath
def create_security_token_from_csr():
        #Creating and returning token, secret - Farook
        try:
                with open("mycscsr2.csr", "r") as f:
                    csr_contents = f.read()
        except Exception as e:
                print(str(e))
        base64csr = base64.b64encode(csr_contents.encode("utf-8")).decode("utf-8")
        url = "https://gw-fatoora.zatca.gov.sa/e-invoicing/developer-portal/compliance"
        payload = json.dumps({
        "csr": base64csr
        })
        headers = {
        'accept': 'application/json',
        'OTP': '123345',
        'Accept-Version': 'V2',
        'Content-Type': 'application/json',
        'Cookie': 'TS0106293e=0132a679c07382ce7821148af16b99da546c13ce1dcddbef0e19802eb470e539a4d39d5ef63d5c8280b48c529f321e8b0173890e4f'
        }
        response = requests.request("POST", url, headers=headers, data=payload)
        data=json.loads(response.text)
        # print(data)
        return data["binarySecurityToken"],  data["secret"]
#All functions end here. Execution starts from here.
def add_Static_Valueto_Xml():
    success = True
    sbXml = chilkat2.StringBuilder()
    success = sbXml.LoadFile("/opt/oxy/frappe-bench/apps/saudi_phase2_api/saudi_phase2_api/saudi_phase2_api/test_chilkat.xml","utf-8")
    if (success == False):
        print("Failed to load XML file to be signed.")
        sys.exit()
    gen = chilkat2.XmlDSigGen()

    gen.SigLocation = "Invoice|ext:UBLExtensions|ext:UBLExtension|ext:ExtensionContent|sig:UBLDocumentSignatures|sac:SignatureInformation"
    gen.SigLocationMod = 0
    gen.SigId = "signature"
    gen.SigNamespacePrefix = "ds"
    gen.SigNamespaceUri = "http://www.w3.org/2000/09/xmldsig#"
    gen.SignedInfoCanonAlg = "C14N_11"
    gen.SignedInfoDigestMethod = "sha256"
    object1 = chilkat2.Xml()
    object1.Tag = "xades:QualifyingProperties"
    object1.AddAttribute("xmlns:xades","http://uri.etsi.org/01903/v1.3.2#")
    object1.AddAttribute("Target","signature")
    object1.UpdateAttrAt("xades:SignedProperties",True,"Id","xadesSignedProperties")
    object1.UpdateChildContent("xades:SignedProperties|xades:SignedSignatureProperties|xades:SigningTime","TO BE GENERATED BY CHILKAT")
    object1.UpdateAttrAt("xades:SignedProperties|xades:SignedSignatureProperties|xades:SigningCertificate|xades:Cert|xades:CertDigest|ds:DigestMethod",True,"Algorithm","http://www.w3.org/2001/04/xmlenc#sha256")
    object1.UpdateChildContent("xades:SignedProperties|xades:SignedSignatureProperties|xades:SigningCertificate|xades:Cert|xades:CertDigest|ds:DigestValue","TO BE GENERATED BY CHILKAT")
    object1.UpdateChildContent("xades:SignedProperties|xades:SignedSignatureProperties|xades:SigningCertificate|xades:Cert|xades:IssuerSerial|ds:X509IssuerName","TO BE GENERATED BY CHILKAT")
    object1.UpdateChildContent("xades:SignedProperties|xades:SignedSignatureProperties|xades:SigningCertificate|xades:Cert|xades:IssuerSerial|ds:X509SerialNumber","TO BE GENERATED BY CHILKAT")
    gen.AddObject("",object1.GetXml(),"","")
    xml1 = chilkat2.Xml()
    xml1.Tag = "ds:Transforms"
    xml1.UpdateAttrAt("ds:Transform",True,"Algorithm","http://www.w3.org/TR/1999/REC-xpath-19991116")
    xml1.UpdateChildContent("ds:Transform|ds:XPath","not(//ancestor-or-self::ext:UBLExtensions)")
    xml1.UpdateAttrAt("ds:Transform[1]",True,"Algorithm","http://www.w3.org/TR/1999/REC-xpath-19991116")
    xml1.UpdateChildContent("ds:Transform[1]|ds:XPath","not(//ancestor-or-self::cac:Signature)")
    xml1.UpdateAttrAt("ds:Transform[2]",True,"Algorithm","http://www.w3.org/TR/1999/REC-xpath-19991116")
    xml1.UpdateChildContent("ds:Transform[2]|ds:XPath","not(//ancestor-or-self::cac:AdditionalDocumentReference[cbc:ID='QR'])")
    xml1.UpdateAttrAt("ds:Transform[3]",True,"Algorithm","http://www.w3.org/2006/12/xml-c14n11")
    gen.AddSameDocRef2("","sha256",xml1,"")
    gen.SetRefIdAttr("","invoiceSignedData")
    gen.AddObjectRef("xadesSignedProperties","sha256","","","http://www.w3.org/2000/09/xmldsig#SignatureProperties")
    return gen,sbXml  

# add_Static_Valueto_Xml()
# sys.exit()
def load_certificate(): 
    gen ,sbXml= add_Static_Valueto_Xml()
    certFromPfx = chilkat2.Cert()
    success = certFromPfx.LoadPfxFile("/opt/oxy/frappe-bench/sites/mycert.pfx","Friday2000@T")
    if (success != True):
        print(certFromPfx.LastErrorText)
        sys.exit()
    else:
        print("success")
    success = gen.SetX509Cert(certFromPfx,True)
    if (success != True):
        print(gen.LastErrorText)
        sys.exit()
    gen.KeyInfoType = "X509Data"
    gen.X509Type = "Certificate"
    gen.Behaviors = "IndentedSignature,TransformSignatureXPath,ZATCA"
    success = gen.CreateXmlDSigSb(sbXml)
    if (success != True):
        print(gen.LastErrorText)
        sys.exit()
    else:
        print("success 69")
    return sbXml
# load_certificate()
# sys.exit()
def create_File_SignedXML():
    sbXml= load_certificate()
    success = sbXml.WriteFile("signedXml.xml","utf-8",False)
    # print(sbXml.GetAsString())
    return sbXml
# create_File_SignedXML()
# sys.exit()
def zatca_Verification():
    sbXml = create_File_SignedXML()
    verifier = chilkat2.XmlDSig()
    success = verifier.LoadSignatureSb(sbXml)
    if (success != True):
        print(verifier.LastErrorText)
        sys.exit()
    verifier.UncommonOptions = "ZATCA"
    numSigs = verifier.NumSignatures
    verifyIdx = 0
    while verifyIdx < numSigs :
        verifier.Selector = verifyIdx
        verified = verifier.VerifySignature(True)
        if (verified != True):
            print(verifier.LastErrorText)
            sys.exit()
        verifyIdx = verifyIdx + 1

    print("All signatures were successfully verified.")
    
# zatca_Verification()
# sys.exit()
def qrcode_Creation():
    sellerName = "Firoz Ashraf"
    vatNumber = "1234567891"
    timeStamp = "2021-11-17 08:30:00"
    invoiceTotal = "100.00"
    vatTotal = "15.00"
    bdTlv = chilkat2.BinData()
    charset = "utf-8"
    tag = 1
    bdTlv.AppendByte(tag)
    bdTlv.AppendCountedString(1,False,sellerName,charset)
    tag = tag + 1
    
    length = len( bdTlv.GetEncoded("base64") )
    print("Length of the tag1:", length)
    # This is tag 2
    bdTlv.AppendByte(tag)
    bdTlv.AppendCountedString(1,False,vatNumber,charset)
    tag = tag + 1
    length = len( bdTlv.GetEncoded("base64") )
    print("Length of the tag2:", length)
    # This is tag 3
    bdTlv.AppendByte(tag)
    bdTlv.AppendCountedString(1,False,timeStamp,charset)
    tag = tag + 1
    length = len( bdTlv.GetEncoded("base64") )
    print("Length of the tag3:", length)
    # This is tag 4
    bdTlv.AppendByte(tag)
    bdTlv.AppendCountedString(1,False,invoiceTotal,charset)
    tag = tag + 1
    length = len( bdTlv.GetEncoded("base64") )
    print("Length of the tag4:", length)
    # This is tag 5
    bdTlv.AppendByte(tag)
    bdTlv.AppendCountedString(1,False,vatTotal,charset)
    length = len( bdTlv.GetEncoded("base64") )
    print("Length of the tag5:", length)
    sbDigestValue, xmlSigned, signedXmlFilePath = get_signed_xml_invoice_for_clearance()
    print("success upto 153")
  
    tag = 6
    bdTlv.AppendByte(tag)
    bdTlv.AppendByte(sbDigestValue.Length)
    bdTlv.AppendSb(sbDigestValue,"utf-8")
    length = len( bdTlv.GetEncoded("base64") )
    print("Length of the tag6:", length)
    sbSignatureValue = chilkat2.StringBuilder()
    success = xmlSigned.GetChildContentSb("ext:UBLExtensions|ext:UBLExtension|ext:ExtensionContent|sig:UBLDocumentSignatures|sac:SignatureInformation|ds:Signature|ds:SignatureValue",sbSignatureValue)
    if (success == False):
        print("Failed to get SignatureValue from signed XML.")
        sys.exit()
    # print("SignatureValue = " + sbSignatureValue.GetAsString())
    tag = 7
    bdTlv.AppendByte(tag)
    bdTlv.AppendByte(sbSignatureValue.Length)
    bdTlv.AppendSb(sbSignatureValue,"utf-8")
    length = len( bdTlv.GetEncoded("base64") )
    print("Length of the tag7:", length)
    # x509Certificate = xmlSigned.GetChildContent("ext:UBLExtensions|ext:UBLExtension|ext:ExtensionContent|sig:UBLDocumentSignatures|sac:SignatureInformation|ds:Signature|ds:KeyInfo|ds:X509Data|ds:X509Certificate")
    # if (xmlSigned.LastMethodSuccess == False):
    #     print("Failed to get X509Certificate from the signed XML.")
    #     sys.exit()
    # print()

    # cert = chilkat2.Cert()

    # success = cert.SetFromEncoded(x509Certificate)
    # if (success == False):
    #     print("Failed to load signing certificate from base64.")
    #     sys.exit()
    # bdPubKey = chilkat2.BinData()
    # success = cert.GetPubKeyDer(True,bdPubKey)
    # if (success == False):
    #     print("Failed to get certificate's public key.")
    #     sys.exit()
    # tag = 8
    # bdTlv.AppendByte(tag)
    # bdTlv.AppendByte(bdPubKey.NumBytes)
    # bdTlv.AppendBd(bdPubKey)
    # length = len( bdTlv.GetEncoded("base64") )
    # print("Length of the tag8:", length)
    # # print("Certificate public key:")
    # # print(bdPubKey.GetEncoded("base64"))

    # bdCertSig = chilkat2.BinData()
    # success = cert.GetSignature(bdCertSig)
    # if (success == False):
    #     print("Failed to get certificate's signature.")
    #     sys.exit()
    # # else:
    # #     print("success 168")
    # tag = 9
    # bdTlv.AppendByte(tag)
    # bdTlv.AppendByte(bdCertSig.NumBytes)
    # bdTlv.AppendBd(bdCertSig)
    # length = len( bdTlv.GetEncoded("base64") )
    # print("Length of the tag9:", length)
    # # print("Certificate signature:")
    # # print(bdCertSig.GetEncoded("hex"))
    # # print(bdTlv.GetEncoded("base64"))
    qr_base64 = bdTlv.GetEncoded("base64")
    # print("QR: " + qr_base64)

#code which i tried to short the qr content
#     corrected_invoice_data = bdTlv.GetEncoded("base64") 
# # Create a QR code instance
#     qr = qrcode.QRCode(
#         version=1,
#         error_correction=qrcode.constants.ERROR_CORRECT_L,
#         box_size=10,
#     border=4,
# )
#     qr.add_data(corrected_invoice_data)
#     qr.make(fit=True)
#     print(corrected_invoice_data)  # Display the corrected QR data as text

    print("success qr code creation")
    return bdTlv
# qrcode_Creation()
# sys.exit()
def hardcode_qrcode():
    qrcode=" AQxGaXJveiBBc2hyYWYCCjEyMzQ1Njc4OTEDEzIwMjEtMTEtMTcgMDg6MzA6MDAEBjEwMC4wMAUFMTUuMDAGLHhHNWhNM2VtL0E2ajJPNUg0Q2g1TkdFL01NSVhycEdkWFNpYVo0NkRmYjg9B/9qZ0UzSXpxaElSczJ4TnAyWFBxZCtsQzVXNEpXQWhka056NVhkOGtKQUhCSFUzWGV2N1FQQWRseXM5UEtGRlN1c0JPWkpRSmJyTEN5MWYwMHNncWFSdkxndFk1dW1XN0xXMnJiYnBLNzhobnptY24xOGh6c2RyKzdjeFMrRGR5cmk1aSt1V2I5QWpNVmhVR3NWa3FOcjJaMXVQNzJzbzJmbUlXOGlBRFJ0cmtPWmFYMkdJemE4bDYwaEN3UFpTdFpnNFNmVkVWbk5VcXlXbUZWZi9YdkViYXdnQVg0SEtqeGIwNE5JSXhpUFhZUVZ0ZjBwakhWQUVidUwvanp2KzFRWkZOKzRNNG92RjFvWnpaUDVLNEdZZExmRG91bFhCbFdnbFFYbFJyLzBIY2JieEhRZWgzQnJUbHpJeVdSRVpQOHlsd0Y1WWVRQkxxbGRHc2RKMkN1dFE9PQj/MIIBCgKCAQEAvUI4k3a7/XoBCbm8hul3r8otO4Nr9B4f8Lz71J03B12RUTUaLoDVVcbKIBZNLFcgFS4CXhGmwF3BfDXEwz4O/LXI9LXfcSGrENp0VhHmQaobNxnNKiL+5CFy/zo1EymH69t2dTFxpY92cgaatQLJoaAmWyrJGzKa0irxu1XXEfQlkko65NNzmLg6xvIhJNDFE7l1ddPu7sfQFi2Xp/CTcUy6x0sQFVyQ6MBdJVVuY1KzRhg3EBN/a/DHDYULFShD8Me+VX95/d/2T8nGyWETjGIEpId6zk0xbRNax5XpXsBDxf7qlIchagMCWRs2H8Pt6zCZj5Y79iR1LLcj2zeVbQIDAQABCf898I0jHdhvolPaBvvg+DRNnm9xPu7iCNwXFMqxK/vyZDP8VcNLx8wOdwYlDVNBgnclgpwUU3WoqIKyF44U7fWN1MRMl9fGQa7AOtKxlkJ8vWdDPMzY03J1rrfWpA0FYShLzKoAmCAETOnv6Xk3qqvmh4t1VAWQsWoBG8rWhnrGDc6CBl3O36CLJO6qJpXvPoUOQ/Jz0QeRl6YMDOQIi0npnKfOlU5snSHshz2H9uxTHvQZGs9d1xfijLgqQqr/twZQKvs0H8+T4x1q5V3VnvdrqIz/RT6YQp0C46baCbrveYaspy/Y/3HRouU3IfHEA1Pc/Da3n5/gTJcc/PSjXdOU"
    print("success qr code creation")
    return qrcode

def add_QRcodeto_Xml():
    bdTlv = qrcode_Creation()
    # qr=hardcode_qrcode()
    signedXmlFilePath = "/opt/oxy/frappe-bench/sites/signedXml.xml"    # doubt to pass signedxml file path
    xmlQR = chilkat2.Xml()
    xmlQR.Tag = "cac:AdditionalDocumentReference"
    xmlQR.UpdateChildContent("cbc:ID","QR")
    xmlQR.UpdateAttrAt("cac:Attachment|cbc:EmbeddedDocumentBinaryObject",True,"mimeCode","text/plain")
    # xmlQR.UpdateChildContent("cac:Attachment|cbc:EmbeddedDocumentBinaryObject",bdTlv.GetEncoded("base64"))
    # xmlQR.UpdateChildContent("cac:Attachment|cbc:EmbeddedDocumentBinaryObject","Testing my QR Code 333")
    sbSignedXml = chilkat2.StringBuilder()
    success = sbSignedXml.LoadFile(signedXmlFilePath,"utf-8")
    if (success == False):
        print("Failed to load previously signed XML file.")
        sys.exit()
    else:
         print("Success at 326")
    # sys.exit()
    sbReplaceStr = chilkat2.StringBuilder()
    xmlQR.EmitXmlDecl = False
    xmlQR.EmitCompact = True
    # print(xmlQR.GetXml())  # this is the new with My QR Code 333
    # sbReplaceStr.Append(xmlQR.GetXml())  
    # print("  ")
    # print(sbReplaceStr.GetAsString())
    # print("  ")
    # print("  ")
    # print(sbReplaceStr.GetAsString())
    # print("  ")
    # # sbReplaceStr.Append("<cac:Signature>")
    # print("  ")
    # print(sbReplaceStr.GetAsString())
    # print("  ")
    # sample_2 = "<cac:Signature>"
    sample_string = '''GsiuvGjvchjbFhibcDhjv1886G'''
    # print(sbReplaceStr.GetAsString())
    success = sbSignedXml.ReplaceFirst(sample_string,bdTlv.GetEncoded("base64"))
    # success = sbSignedXml.ReplaceFirst(sample_string,qr)
    if success == False:
        print("Failed to replace <cac:Signature> with QR code in the signed XML.")
        sys.exit()
    else:
        print("  ")
        print("replace success")
    print(sbSignedXml.GetAsString())
    # sys.exit()
    if (success == False):
        print("Did not find <cac:Signature> in the signed XML")
        sys.exit()

    success = sbSignedXml.WriteFile("signedXML_withQR.xml","utf-8",False)
    print("suceess add qr code")
# add_QRcodeto_Xml()
# sys.exit()
    return sbSignedXml
def verify_SignXML_withQR():
    sbSignedXml = add_QRcodeto_Xml()
    verifier = chilkat2.XmlDSig()
    success = verifier.LoadSignatureSb(sbSignedXml)
    if (success != True):
        print(verifier.LastErrorText)
        sys.exit()
    # else:
    #     print("success 205")
    verifier.UncommonOptions = "ZATCA"

    numSigs = verifier.NumSignatures
    verifyIdx = 0
    while verifyIdx < numSigs :
        verifier.Selector = verifyIdx
        verified = verifier.VerifySignature(True)
        if (verified != True):
            print(verifier.LastErrorText)
            sys.exit()

        verifyIdx = verifyIdx + 1
    print("All signatures were successfully verified.")
# verify_SignXML_withQR()
# sys.exit()
def signedXml_Withtoken():
    otp = "123345"
    # signedXmlFilePath = "/opt/oxy/frappe-bench/sites/signedXML_withQR.xml"
    signedXmlFilePath = "/opt/oxy/frappe-bench/sites/signedXml.xml"    # doubt to pass signedxml file path
    token,secret = create_security_token_from_csr()
    print("success line upto 403")
    # print(token)
    # print(secret)
    # sys.exit()
    pem = chilkat2.Pem()
    # test_Csr_Call()
    signedXml = chilkat2.Xml()
    success = signedXml.LoadXmlFile(signedXmlFilePath)
    if (success == False):
        print(signedXml.LastErrorText)
        sys.exit()
    else:
         print("success 407")
    return signedXml
# signedXml_Withtoken()
# sys.exit()
def get_InvoiceHash():
    signedXml = signedXml_Withtoken()
    invoiceHash = signedXml.GetChildContent("ext:UBLExtensions|ext:UBLExtension|ext:ExtensionContent|sig:UBLDocumentSignatures|sac:SignatureInformation|ds:Signature|ds:SignedInfo|ds:Reference[0]|ds:DigestValue")
    # print(invoiceHash)
    # return 
    return invoiceHash
# get_InvoiceHash()
# sys.exit()
def  get_UUID():
    signedXml = signedXml_Withtoken()
    cbc_UUID = signedXml.GetChildContent("cbc:UUID")
    # print(cbc_UUID)
    return cbc_UUID
# get_UUID()

send_invoice_for_clearance_normal()
sys.exit()