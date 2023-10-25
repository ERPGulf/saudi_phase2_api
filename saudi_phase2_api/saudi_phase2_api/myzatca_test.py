import frappe
frappe.init(site="husna.erpgulf.com")
frappe.connect()
import os 
from subprocess import call
import subprocess
import requests
import json
import base64
from fatoora import Fatoora
import sys
import time
from frappe.utils.data import add_to_date, get_time, getdate
import OpenSSL
import chilkat2
from lxml import etree
import re

def send_invoice_for_clearance_normal(uuid,invoiceHash):
                    signedXmlFilePath = "/opt/oxy/frappe-bench/sites/signedXML_withQR.xml"
                    token,secret = create_security_token_from_csr()
                    with open(signedXmlFilePath, "r") as file:
                        xml = file.read().lstrip()
                        base64_encoded = base64.b64encode(xml.encode("utf-8"))
                        base64_decoded = base64_encoded.decode("utf-8")
                    url = "https://gw-fatoora.zatca.gov.sa/e-invoicing/developer-portal/compliance/invoices"
                    payload = json.dumps({
                    "invoiceHash": invoiceHash,
                    "uuid": uuid,
                    "invoice": base64_decoded
                    })
                    headers = { 
                        'accept': 'application/json',
                        'Accept-Language': 'en',
                        'Accept-Version': 'V2',
                        'Authorization': "Basic VFVsSlJERnFRME5CTTNsblFYZEpRa0ZuU1ZSaWQwRkJaVFJUYUhOMmVXNDNNREo1VUhkQlFrRkJRamRvUkVGTFFtZG5jV2hyYWs5UVVWRkVRV3BDYWsxU1ZYZEZkMWxMUTFwSmJXbGFVSGxNUjFGQ1IxSlpSbUpIT1dwWlYzZDRSWHBCVWtKbmIwcHJhV0ZLYXk5SmMxcEJSVnBHWjA1dVlqTlplRVo2UVZaQ1oyOUthMmxoU21zdlNYTmFRVVZhUm1ka2JHVklVbTVaV0hBd1RWSjNkMGRuV1VSV1VWRkVSWGhPVlZVeGNFWlRWVFZYVkRCc1JGSlRNVlJrVjBwRVVWTXdlRTFDTkZoRVZFbDVUVVJaZUUxNlJURk5la1V3VG14dldFUlVTVEJOUkZsNFRXcEZNVTE2UlRCT2JHOTNVMVJGVEUxQmEwZEJNVlZGUW1oTlExVXdSWGhFYWtGTlFtZE9Wa0pCYjFSQ1YwWnVZVmQ0YkUxU1dYZEdRVmxFVmxGUlRFVjNNVzlaV0d4b1NVaHNhRm95YUhSaU0xWjVUVkpKZDBWQldVUldVVkZFUlhkcmVFMXFZM1ZOUXpSM1RHcEZkMVpxUVZGQ1oyTnhhR3RxVDFCUlNVSkNaMVZ5WjFGUlFVTm5Ua05CUVZSVVFVczViSEpVVm10dk9YSnJjVFphV1dOak9VaEVVbHBRTkdJNVV6UjZRVFJMYlRkWldFb3JjMjVVVm1oTWEzcFZNRWh6YlZOWU9WVnVPR3BFYUZKVVQwaEVTMkZtZERoREwzVjFWVms1TXpSMmRVMU9ielJKUTB0cVEwTkJhVmwzWjFselIwRXhWV1JGVVZOQ1ozcERRbWRMVWl0TlNIZDRTRlJCWWtKblRsWkNRVkZOUmtSRmRHRkhSalZaV0hkNVRGUkplazVJZDNwTVZFVjRUV3BOZWsxU09IZElVVmxMUTFwSmJXbGFVSGxNUjFGQ1FWRjNVRTE2VFhoTlZGbDVUMFJaTlU1RVFYZE5SRUY2VFZFd2QwTjNXVVJXVVZGTlJFRlJlRTFVUVhkTlVrVjNSSGRaUkZaUlVXRkVRV2hoV1ZoU2FsbFRRWGhOYWtWWlRVSlpSMEV4VlVWRWQzZFFVbTA1ZGxwRFFrTmtXRTU2WVZjMWJHTXpUWHBOUWpCSFFURlZaRVJuVVZkQ1FsTm5iVWxYUkRaaVVHWmlZa3RyYlZSM1QwcFNXSFpKWWtnNVNHcEJaa0puVGxaSVUwMUZSMFJCVjJkQ1VqSlpTWG8zUW5GRGMxb3hZekZ1WXl0aGNrdGpjbTFVVnpGTWVrSlBRbWRPVmtoU09FVlNla0pHVFVWUFoxRmhRUzlvYWpGdlpFaFNkMDlwT0haa1NFNHdXVE5LYzB4dWNHaGtSMDVvVEcxa2RtUnBOWHBaVXpsRVdsaEtNRkpYTlhsaU1uaHpUREZTVkZkclZrcFViRnBRVTFWT1JreFdUakZaYTA1Q1RGUkZkVmt6U25OTlNVZDBRbWRuY2tKblJVWkNVV05DUVZGVFFtOUVRMEp1VkVKMVFtZG5ja0puUlVaQ1VXTjNRVmxhYVdGSVVqQmpSRzkyVEROU2VtUkhUbmxpUXpVMldWaFNhbGxUTlc1aU0xbDFZekpGZGxFeVZubGtSVloxWTIwNWMySkRPVlZWTVhCR1lWYzFNbUl5YkdwYVZrNUVVVlJGZFZwWWFEQmFNa1kyWkVNMWJtSXpXWFZpUnpscVdWZDRabFpHVG1GU1ZXeFBWbXM1U2xFd1ZYUlZNMVpwVVRCRmRFMVRaM2hMVXpWcVkyNVJkMHQzV1VsTGQxbENRbEZWU0UxQlIwZElNbWd3WkVoQk5reDVPVEJqTTFKcVkyMTNkV1Z0UmpCWk1rVjFXakk1TWt4dVRtaE1NamxxWXpOQmQwUm5XVVJXVWpCUVFWRklMMEpCVVVSQloyVkJUVUl3UjBFeFZXUktVVkZYVFVKUlIwTkRjMGRCVVZWR1FuZE5RMEpuWjNKQ1owVkdRbEZqUkVGNlFXNUNaMnR5UW1kRlJVRlpTVE5HVVc5RlIycEJXVTFCYjBkRFEzTkhRVkZWUmtKM1RVTk5RVzlIUTBOelIwRlJWVVpDZDAxRVRVRnZSME5EY1VkVFRUUTVRa0ZOUTBFd1owRk5SVlZEU1ZGRVQxQXdaakJFY21oblpVUlVjbFpNZEVwMU9HeFhhelJJU25SbFkyWTFabVpsVWt4blpVUTRZMlZWWjBsblpFSkNUakl4U1RNM2FYTk5PVlZ0VTFGbE9IaFNjRWh1ZDA5NFNXYzNkMDR6V1RKMlZIQnpVR2hhU1QwPTpFcGo2OUdoOFRNTXpZZktsdEx2MW9tWktyaWUwc1A2TEF2YW1iUUZIVGd3PQ==",
                        'Content-Type': 'application/json'
                    }
                    try:
                        response = requests.request("POST", url, headers=headers, data=payload)
                    except Exception as e:    
                        print(str(e)) 
                        sys.exit()
                    return response.text
                    
def get_signed_xml_invoice_for_clearance():
                signedXmlFilePath = "/opt/oxy/frappe-bench/sites/signedXml.xml"
                xmlSigned = chilkat2.Xml()
                success = xmlSigned.LoadXmlFile(signedXmlFilePath)
                if (success == False):
                    print(xmlSigned.LastErrorText)
                    sys.exit()
                sbDigestValue = chilkat2.StringBuilder()
                success = xmlSigned.GetChildContentSb("ext:UBLExtensions|ext:UBLExtension|ext:ExtensionContent|sig:UBLDocumentSignatures|sac:SignatureInformation|ds:Signature|ds:SignedInfo|ds:Reference[0]|ds:DigestValue",sbDigestValue)
                if (success == False):
                    print("Failed to get DigestValue from signed XML.")
                    sys.exit()
                return sbDigestValue, xmlSigned, signedXmlFilePath
def create_security_token_from_csr():
                #Creating and returning token, secret 
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
                return data["binarySecurityToken"],  data["secret"]

def  get_Issue_Time(invoice_number):
                doc = frappe.get_doc("Sales Invoice", invoice_number)
                time = get_time(doc.posting_time)
                issue_time = time.strftime("%H:%M:%S")
                return issue_time

def get_Tax_for_Item(full_string,item):
                data = json.loads(full_string)
                tax_percentage=data.get(item,[0,0])[0]
                tax_amount = data.get(item, [0, 0])[1]
                return tax_amount,tax_percentage

def get_Actual_Value_And_Rendering(invoice_number):
                e_invoice_items = []
                doc = frappe.get_doc("Sales Invoice", invoice_number) 
                company_doc = frappe.get_doc("Company", doc.company)
                customer_doc= frappe.get_doc("Customer",doc.customer)
                for item in doc.items:
                    item_tax_amount,item_tax_percentage =  get_Tax_for_Item(doc.taxes[0].item_wise_tax_detail,item.item_code)
                    item_data = {
                        "qty": item.qty,
                        "amount": item.amount,
                        "item_tax_percentage" : item_tax_percentage,
                        "item_character":doc.custom_item_character,
                        "item_tax_amount":item_tax_amount,
                        "base_net_amount": item.amount + item_tax_amount,
                        "item_code": item.item_code,
                        "price_list_rate": item.price_list_rate,
                    }
                    e_invoice_items.append(item_data)
                    context = { "doc": {
                                    "document_id":doc.custom_document_id,
                                    "doc_uuid" : doc.custom_doc_uuid,
                                    "acccustid":customer_doc.custom_accounting_customer_id,
                                    "accsupid":company_doc.custom_accounting_supplier_party_id,
                                    "invoice_number":doc.custom_invoice,
                                    "invoice_type_code":doc.custom_invoice_type_code,
                                    "payment_code":doc.custom_payment_code,
                                    "lineCount":doc.custom_total_no_of_line,
                                    "e_invoice_items": e_invoice_items,
                                    "company_tax_id":company_doc.tax_id,
                                    "uuid":doc.custom_uuid,
                                    "posting_date": doc.posting_date,
                                    "qr_code": "GsiuvGjvchjbFhibcDhjv1886G",
                                    "posting_time":get_Issue_Time(invoice_number),
                                    "company": doc.company,
                                    "currency":doc.currency,
                                    "customer": doc.customer,
                                    "total": doc.base_net_total,                                       
                                    "pih": doc.custom_pih,
                                    "total_taxes_and_charges": doc.base_total_taxes_and_charges,
                                    "total": doc.total,
                                    "grand_total": doc.grand_total,
                                    "tax_rate":doc.taxes[0].rate,
                                    "company_address_data":{
                                                "sub":company_doc.custom_sub,
                                                "building_no": company_doc.custom_build_no,
                                                "street": company_doc.custom_street,
                                                "city":company_doc.custom_city,
                                                "pincode": company_doc.custom_pincode,
                                                "state": company_doc.custom_state,
                                                "plot_id_no": company_doc.custom_plot_id_no,
                                                "country":company_doc.custom_country_name},
                                    "customer_address_data": {
                                                "street": customer_doc.custom_street,
                                                "building_no": customer_doc.custom_building_no,
                                                "sub":customer_doc.custom_sub,
                                                "city":customer_doc.custom_city,
                                                "pincode": customer_doc.custom_pincode,
                                                "state": customer_doc.custom_state,
                                                "plot_id_no":customer_doc.custom_plot_id_no,
                                                "country":customer_doc.custom_country},}}
                    invoice_xml = frappe.render_template("saudi_phase2_api/saudi_phase2_api/e_test.xml", context)
                    print(invoice_xml)
                    with open("e_invoice.xml", "w") as file:
                        file.write(invoice_xml)

def add_Static_Valueto_Xml():
                    success = True
                    sbXml = chilkat2.StringBuilder()
                    success = sbXml.LoadFile("/opt/oxy/frappe-bench/sites/e_invoice.xml","utf-8")
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

def load_certificate(gen,sbXml): 
                    certFromPfx = chilkat2.Cert()
                    success = certFromPfx.LoadPfxFile("/opt/oxy/frappe-bench/sites/mycert.pfx","Friday2000@T")
                    if (success != True):
                        print(certFromPfx.LastErrorText)
                        sys.exit()
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
                    return sbXml

def create_File_SignedXML(sbXml):
                    success = sbXml.WriteFile("signedXml.xml","utf-8",False)
                    return sbXml

def zatca_Verification(sbXml):
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
                    bdTlv.AppendByte(tag)
                    bdTlv.AppendCountedString(1,False,vatNumber,charset)
                    tag = tag + 1
                    bdTlv.AppendByte(tag)
                    bdTlv.AppendCountedString(1,False,timeStamp,charset)
                    tag = tag + 1
                    bdTlv.AppendByte(tag)
                    bdTlv.AppendCountedString(1,False,invoiceTotal,charset)
                    tag = tag + 1
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
                    sbSignatureValue = chilkat2.StringBuilder()
                    success = xmlSigned.GetChildContentSb("ext:UBLExtensions|ext:UBLExtension|ext:ExtensionContent|sig:UBLDocumentSignatures|sac:SignatureInformation|ds:Signature|ds:SignatureValue",sbSignatureValue)
                    if (success == False):
                        print("Failed to get SignatureValue from signed XML.")
                        sys.exit()
                    qr_base64 = bdTlv.GetEncoded("base64")
                    print("success qr code creation")
                    return bdTlv

def add_QRcode_To_Xml(bdTlv):
                    signedXmlFilePath = "/opt/oxy/frappe-bench/sites/signedXml.xml"   
                    xmlQR = chilkat2.Xml()
                    xmlQR.Tag = "cac:AdditionalDocumentReference"
                    xmlQR.UpdateChildContent("cbc:ID","QR")
                    xmlQR.UpdateAttrAt("cac:Attachment|cbc:EmbeddedDocumentBinaryObject",True,"mimeCode","text/plain")
                    sbSignedXml = chilkat2.StringBuilder()
                    success = sbSignedXml.LoadFile(signedXmlFilePath,"utf-8")
                    if (success == False):
                        print("Failed to load previously signed XML file.")
                        sys.exit()
                    sbReplaceStr = chilkat2.StringBuilder()
                    xmlQR.EmitXmlDecl = False
                    xmlQR.EmitCompact = True
                    sample_string = '''GsiuvGjvchjbFhibcDhjv1886G'''
                    success = sbSignedXml.ReplaceFirst(sample_string,bdTlv.GetEncoded("base64"))
                    if success == False:
                        print("Failed to replace <cac:Signature> with QR code in the signed XML.")
                        sys.exit()
                    print(sbSignedXml.GetAsString())
                    if (success == False):
                        print("Did not find <cac:Signature> in the signed XML")
                        sys.exit()
                    success = sbSignedXml.WriteFile("signedXML_withQR.xml","utf-8",False)
                    print("suceess add qr code")
                    return sbSignedXml

def verify_SignXML_withQR(sbSignedXml):
                        verifier = chilkat2.XmlDSig()
                        success = verifier.LoadSignatureSb(sbSignedXml)
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
                   
def signedXml_Withtoken():
                        otp = "123345"
                        signedXmlFilePath = "/opt/oxy/frappe-bench/sites/signedXml.xml"    
                        token,secret = create_security_token_from_csr()
                        pem = chilkat2.Pem()
                        signedXml = chilkat2.Xml()
                        success = signedXml.LoadXmlFile(signedXmlFilePath)
                        if (success == False):
                            print(signedXml.LastErrorText)
                            sys.exit()
                        return signedXml

def get_InvoiceHash(signedXml):
                        invoiceHash = signedXml.GetChildContent("ext:UBLExtensions|ext:UBLExtension|ext:ExtensionContent|sig:UBLDocumentSignatures|sac:SignatureInformation|ds:Signature|ds:SignedInfo|ds:Reference[0]|ds:DigestValue")
                        return invoiceHash

def  get_UUID(signedXml):
                        cbc_UUID = signedXml.GetChildContent("cbc:UUID")
                        uuid  =cbc_UUID
                        print(cbc_UUID)
                        return uuid

@frappe.whitelist(allow_guest=True)
def invoice_Zatca_call(invoice_number):
                        get_Actual_Value_And_Rendering(invoice_number)
                        gen ,sbXml  =  add_Static_Valueto_Xml()  
                        sbXml = load_certificate(gen,sbXml)
                        sbXml= create_File_SignedXML(sbXml)
                        zatca_Verification(sbXml) 
                        bdTlv = qrcode_Creation()
                        sbSignedXml= add_QRcode_To_Xml(bdTlv)
                        verify_SignXML_withQR(sbSignedXml)  
                        signedXml=signedXml_Withtoken()
                        invoiceHash=get_InvoiceHash(signedXml)    
                        uuid=get_UUID(signedXml)
                        return json.dumps(send_invoice_for_clearance_normal(uuid,invoiceHash))

