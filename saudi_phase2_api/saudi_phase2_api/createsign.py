import frappe
# frappe.init(site="husna.erpgulf.com")
# frappe.connect()
import xml.etree.ElementTree as ET
import uuid 
import hashlib
import base64
import subprocess
import re
from lxml import etree
import xml.dom.minidom as minidom
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from datetime import datetime
import xml.etree.ElementTree as ET
import json
import html
import xml.etree.ElementTree as ElementTree
import chilkat2
import sys
import frappe 
import requests
from frappe.utils.data import  get_time

invoice_number='ACC-SINV-2023-00022'
sales_invoice_doc = frappe.get_doc('Sales Invoice' ,invoice_number)

def get_Tax_for_Item(full_string,item):
                data = json.loads(full_string)
                tax_percentage=data.get(item,[0,0])[0]
                tax_amount = data.get(item, [0, 0])[1]
                return tax_amount,tax_percentage

def get_ICV_code(invoice_number):
                    icv_code = + int(''.join(filter(str.isdigit, invoice_number))) 
                    return icv_code

def  get_Issue_Time(invoice_number):
                #issuing the posting time 
                doc = frappe.get_doc("Sales Invoice", invoice_number)
                time = get_time(doc.posting_time)
                issue_time = time.strftime("%H:%M:%S")
                return issue_time

def invoice_uuid(invoice_number):
                #uuid saving for invoice which is unique for all invoice
                sales_invoice_doc.custom_uuid = str(uuid.uuid1())
                sales_invoice_doc.save()
                return sales_invoice_doc.custom_uuid   
def xml_tags():      
    invoice = ET.Element("Invoice", xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2" )
    invoice.set("xmlns:cac", "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2")
    invoice.set("xmlns:cbc", "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2")
    invoice.set("xmlns:ext", "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2")
    ubl_extensions = ET.SubElement(invoice, "ext:UBLExtensions")
    ubl_extension = ET.SubElement(ubl_extensions, "ext:UBLExtension")
    extension_uri = ET.SubElement(ubl_extension, "ext:ExtensionURI")
    extension_uri.text = "urn:oasis:names:specification:ubl:dsig:enveloped:xades"
    extension_content = ET.SubElement(ubl_extension, "ext:ExtensionContent")
    UBL_Document_Signatures = ET.SubElement(extension_content , "sig:UBLDocumentSignatures"    )
    UBL_Document_Signatures.set("xmlns:sig" , "urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2")
    UBL_Document_Signatures.set("xmlns:sac" , "urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2")
    UBL_Document_Signatures.set("xmlns:sbc" , "urn:oasis:names:specification:ubl:schema:xsd:SignatureBasicComponents-2")
    Signature_Information = ET.SubElement(UBL_Document_Signatures , "sac:SignatureInformation"  )
    id = ET.SubElement(Signature_Information , "cbc:ID"  )
    id.text = "urn:oasis:names:specification:ubl:signature:1"
    Referenced_SignatureID = ET.SubElement(Signature_Information , "sbc:ReferencedSignatureID"  )
    Referenced_SignatureID.text = "urn:oasis:names:specification:ubl:signature:Invoice"
    Signature = ET.SubElement(Signature_Information , "ds:Signature"  )
    Signature.set("Id" , "signature" )
    Signature.set("xmlns:ds" , "http://www.w3.org/2000/09/xmldsig#" )
    Signed_Info = ET.SubElement(Signature , "ds:SignedInfo"  )
    Canonicalization_Method = ET.SubElement(Signed_Info , "ds:CanonicalizationMethod"  )
    Canonicalization_Method.set("Algorithm" , "http://www.w3.org/2006/12/xml-c14n11"  )
    Signature_Method = ET.SubElement(Signed_Info , "ds:SignatureMethod"  )
    Signature_Method.set("Algorithm" , "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"  )
    Reference = ET.SubElement(Signed_Info , "ds:Reference"  )
    Reference.set("Id"  , "invoiceSignedData")
    Reference.set("URI"  , "")
    Transforms = ET.SubElement(Reference , "ds:Transforms" )
    Transform = ET.SubElement(Transforms , "ds:Transform" )
    Transform.set("Algorithm" , "http://www.w3.org/TR/1999/REC-xpath-19991116")
    XPath = ET.SubElement(Transform , "ds:XPath" )
    XPath.text = "not(//ancestor-or-self::ext:UBLExtensions)"
    Transform2 = ET.SubElement(Transforms , "ds:Transform" )
    Transform2.set("Algorithm" , "http://www.w3.org/TR/1999/REC-xpath-19991116")
    XPath2 = ET.SubElement(Transform2 , "ds:XPath" )
    XPath2.text = "not(//ancestor-or-self::cac:Signature)"
    Transform3 = ET.SubElement(Transforms , "ds:Transform" )
    Transform3.set("Algorithm" , "http://www.w3.org/TR/1999/REC-xpath-19991116")
    XPath3 = ET.SubElement(Transform3 , "ds:XPath" )
    XPath3.text = "not(//ancestor-or-self::cac:AdditionalDocumentReference[cbc:ID='QR'])"
    Transform4 = ET.SubElement(Transforms , "ds:Transform" )
    Transform4.set("Algorithm" , "http://www.w3.org/2006/12/xml-c14n11")
    Diges_Method = ET.SubElement(Reference , "ds:DigestMethod" )
    Diges_Method.set("Algorithm" , "http://www.w3.org/2001/04/xmlenc#sha256")
    Diges_value = ET.SubElement(Reference , "ds:DigestValue" )
    Diges_value.text = "O/vEnAxjLAlw8kQUy8nq/5n8IEZ0YeIyBFvdQA8+iFM="
    Reference2 = ET.SubElement(Signed_Info , "ds:Reference"  )
    Reference2.set("URI" , "#xadesSignedProperties")
    Reference2.set("Type" , "http://www.w3.org/2000/09/xmldsig#SignatureProperties")
    Digest_Method1 = ET.SubElement(Reference2 , "ds:DigestMethod"  )
    Digest_Method1.set("Algorithm" , "http://www.w3.org/2001/04/xmlenc#sha256")
    Digest_value1 = ET.SubElement(Reference2 , "ds:DigestValue"  )
    Digest_value1.text="YjQwZmEyMjM2NDU1YjQwNjM5MTFmYmVkODc4NjM2NTc0N2E3OGFmZjVlMzA1ODAwYWE5Y2ZmYmFjZjRiNjQxNg=="
    Signature_Value = ET.SubElement(Signature , "ds:SignatureValue"  )
    Signature_Value.text = "MEQCIDGBRHiPo6yhXIQ9df6pMEkufcGnoqYaS+O8Jn0xagBiAiBtoxpbrwfEJHhUGQHTqzD1ORX5+Z/tumM0wLfZ4cuYRg=="
    KeyInfo = ET.SubElement(Signature , "ds:KeyInfo"  )
    X509Data = ET.SubElement(KeyInfo , "ds:X509Data"  )
    X509Certificate = ET.SubElement(X509Data , "ds:X509Certificate"  )
    X509Certificate.text = "MIID6TCCA5CgAwIBAgITbwAAf8tem6jngr16DwABAAB/yzAKBggqhkjOPQQDAjBjMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxEzARBgoJkiaJk/IsZAEZFgNnb3YxFzAVBgoJkiaJk/IsZAEZFgdleHRnYXp0MRwwGgYDVQQDExNUU1pFSU5WT0lDRS1TdWJDQS0xMB4XDTIyMDkxNDEzMjYwNFoXDTI0MDkxMzEzMjYwNFowTjELMAkGA1UEBhMCU0ExEzARBgNVBAoTCjMxMTExMTExMTExDDAKBgNVBAsTA1RTVDEcMBoGA1UEAxMTVFNULTMxMTExMTExMTEwMTExMzBWMBAGByqGSM49AgEGBSuBBAAKA0IABGGDDKDmhWAITDv7LXqLX2cmr6+qddUkpcLCvWs5rC2O29W/hS4ajAK4Qdnahym6MaijX75Cg3j4aao7ouYXJ9GjggI5MIICNTCBmgYDVR0RBIGSMIGPpIGMMIGJMTswOQYDVQQEDDIxLVRTVHwyLVRTVHwzLWE4NjZiMTQyLWFjOWMtNDI0MS1iZjhlLTdmNzg3YTI2MmNlMjEfMB0GCgmSJomT8ixkAQEMDzMxMTExMTExMTEwMTExMzENMAsGA1UEDAwEMTEwMDEMMAoGA1UEGgwDVFNUMQwwCgYDVQQPDANUU1QwHQYDVR0OBBYEFDuWYlOzWpFN3no1WtyNktQdrA8JMB8GA1UdIwQYMBaAFHZgjPsGoKxnVzWdz5qspyuZNbUvME4GA1UdHwRHMEUwQ6BBoD+GPWh0dHA6Ly90c3RjcmwuemF0Y2EuZ292LnNhL0NlcnRFbnJvbGwvVFNaRUlOVk9JQ0UtU3ViQ0EtMS5jcmwwga0GCCsGAQUFBwEBBIGgMIGdMG4GCCsGAQUFBzABhmJodHRwOi8vdHN0Y3JsLnphdGNhLmdvdi5zYS9DZXJ0RW5yb2xsL1RTWkVpbnZvaWNlU0NBMS5leHRnYXp0Lmdvdi5sb2NhbF9UU1pFSU5WT0lDRS1TdWJDQS0xKDEpLmNydDArBggrBgEFBQcwAYYfaHR0cDovL3RzdGNybC56YXRjYS5nb3Yuc2Evb2NzcDAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMDMCcGCSsGAQQBgjcVCgQaMBgwCgYIKwYBBQUHAwIwCgYIKwYBBQUHAwMwCgYIKoZIzj0EAwIDRwAwRAIgOgjNPJW017lsIijmVQVkP7GzFO2KQKd9GHaukLgIWFsCIFJF9uwKhTMxDjWbN+1awsnFI7RLBRxA/6hZ+F1wtaqU"
    Object = ET.SubElement(Signature , "ds:Object"  )
    QualifyingProperties = ET.SubElement(Object , "xades:QualifyingProperties"  )
    QualifyingProperties.set("Target" , "signature")
    QualifyingProperties.set("xmlns:xades" , "http://uri.etsi.org/01903/v1.3.2#")
    SignedProperties = ET.SubElement(QualifyingProperties , "xades:SignedProperties"  )
    SignedProperties.set("Id" , "xadesSignedProperties")
    SignedSignatureProperties = ET.SubElement(SignedProperties , "xades:SignedSignatureProperties"  )
    SigningTime = ET.SubElement(SignedSignatureProperties , "xades:SigningTime"  )
    SigningTime.text = "2023-01-24T11:36:34Z"
    SigningCertificate = ET.SubElement(SignedSignatureProperties , "xades:SigningCertificate"  )
    Cert = ET.SubElement(SigningCertificate , "xades:Cert"  )
    CertDigest = ET.SubElement(Cert , "xades:CertDigest"  )
    Digest_Method2 = ET.SubElement(CertDigest , "ds:DigestMethod"  )
    Digest_Value2 = ET.SubElement(CertDigest , "ds:DigestValue"  )
    Digest_Method2.set("Algorithm" , "http://www.w3.org/2001/04/xmlenc#sha256")
    Digest_Value2.text = "YTJkM2JhYTcwZTBhZTAxOGYwODMyNzY3NTdkZDM3YzhjY2IxOTIyZDZhM2RlZGJiMGY0NDUzZWJhYWI4MDhmYg=="
    IssuerSerial = ET.SubElement(Cert , "xades:IssuerSerial"  )
    X509IssuerName = ET.SubElement(IssuerSerial , "ds:X509IssuerName"  )
    X509SerialNumber = ET.SubElement(IssuerSerial , "ds:X509SerialNumber"  )
    X509IssuerName.text = "CN=TSZEINVOICE-SubCA-1, DC=extgazt, DC=gov, DC=local"
    X509SerialNumber.text = "2475382886904809774818644480820936050208702411"
    return invoice

def salesinvoice_data(invoice):
    cbc_ProfileID = ET.SubElement(invoice, "cbc:ProfileID")
    cbc_ProfileID.text = "reporting:1.0"
    cbc_ID = ET.SubElement(invoice, "cbc:ID")
    cbc_ID.text = str(sales_invoice_doc.name)
    cbc_UUID = ET.SubElement(invoice, "cbc:UUID")
    # uuid_str = str(uuid.uuid4())
    cbc_UUID.text = sales_invoice_doc.custom_uuid
    uuid1= cbc_UUID.text
    cbc_IssueDate = ET.SubElement(invoice, "cbc:IssueDate")
    cbc_IssueDate.text = str(sales_invoice_doc.posting_date)
    cbc_IssueTime = ET.SubElement(invoice, "cbc:IssueTime")
    cbc_IssueTime.text = get_Issue_Time(invoice_number)
    cbc_InvoiceTypeCode = ET.SubElement(invoice, "cbc:InvoiceTypeCode")
    cbc_InvoiceTypeCode.set("name", "0100000")
    cbc_InvoiceTypeCode.text = str( sales_invoice_doc.custom_invoice_type_code)
    cbc_DocumentCurrencyCode = ET.SubElement(invoice, "cbc:DocumentCurrencyCode")
    cbc_DocumentCurrencyCode.text = sales_invoice_doc.currency
    cbc_TaxCurrencyCode = ET.SubElement(invoice, "cbc:TaxCurrencyCode")
    cbc_TaxCurrencyCode.text = sales_invoice_doc.currency
    cbc_LineCountNumeric = ET.SubElement(invoice, "cbc:LineCountNumeric")     #doubt
    cbc_LineCountNumeric.text =str( sales_invoice_doc.custom_total_no_of_line)
    cac_AdditionalDocumentReference = ET.SubElement(invoice, "cac:AdditionalDocumentReference")
    cbc_ID_1 = ET.SubElement(cac_AdditionalDocumentReference, "cbc:ID")
    cbc_ID_1.text = sales_invoice_doc.custom_document_id
    cbc_UUID_1 = ET.SubElement(cac_AdditionalDocumentReference, "cbc:UUID")
    cbc_UUID_1.text = str(get_ICV_code(invoice_number))
    return invoice  ,uuid1

        
def additional_Reference(invoice):
    settings=frappe.get_doc('Saudi Zatca settings')
    cac_AdditionalDocumentReference2 = ET.SubElement(invoice, "cac:AdditionalDocumentReference")
    cbc_ID_1_1 = ET.SubElement(cac_AdditionalDocumentReference2, "cbc:ID")
    cbc_ID_1_1.text = "PIH"
    cac_Attachment = ET.SubElement(cac_AdditionalDocumentReference2, "cac:Attachment")
    cbc_EmbeddedDocumentBinaryObject = ET.SubElement(cac_Attachment, "cbc:EmbeddedDocumentBinaryObject")
    cbc_EmbeddedDocumentBinaryObject.set("mimeCode", "text/plain")
    cbc_EmbeddedDocumentBinaryObject.text = settings.pih
# QR CODE ------------------------------------------------------------------------------------------------------------------------------------------------------------------
    cac_AdditionalDocumentReference22 = ET.SubElement(invoice, "cac:AdditionalDocumentReference")
    cbc_ID_1_12 = ET.SubElement(cac_AdditionalDocumentReference22, "cbc:ID")
    cbc_ID_1_12.text = "QR"
    cac_Attachment22 = ET.SubElement(cac_AdditionalDocumentReference22, "cac:Attachment")
    cbc_EmbeddedDocumentBinaryObject22 = ET.SubElement(cac_Attachment22, "cbc:EmbeddedDocumentBinaryObject")
    cbc_EmbeddedDocumentBinaryObject22.set("mimeCode", "text/plain")
    cbc_EmbeddedDocumentBinaryObject22.text = "GsiuvGjvchjbFhibcDhjv1886G"
#END  QR CODE ------------------------------------------------------------------------------------------------------------------------------------------------------------------
    cac_sign = ET.SubElement(invoice, "cac:Signature")
    cbc_id_sign = ET.SubElement(cac_sign, "cbc:ID")
    cbc_method_sign = ET.SubElement(cac_sign, "cbc:SignatureMethod")
    cbc_id_sign.text = "urn:oasis:names:specification:ubl:signature:Invoice"
    cbc_method_sign.text = "urn:oasis:names:specification:ubl:dsig:enveloped:xades"
    return invoice

def company_Data(invoice):
    company_doc = frappe.get_doc("Company", sales_invoice_doc.company)
    cac_AccountingSupplierParty = ET.SubElement(invoice, "cac:AccountingSupplierParty")
    cac_Party_1 = ET.SubElement(cac_AccountingSupplierParty, "cac:Party")
    cac_PartyIdentification = ET.SubElement(cac_Party_1, "cac:PartyIdentification")
    cbc_ID_2 = ET.SubElement(cac_PartyIdentification, "cbc:ID")
    cbc_ID_2.set("schemeID", "MLS")
    cbc_ID_2.text =company_doc.custom_accounting_supplier_party_id
    cac_PostalAddress = ET.SubElement(cac_Party_1, "cac:PostalAddress")
    cbc_StreetName = ET.SubElement(cac_PostalAddress, "cbc:StreetName")
    cbc_StreetName.text = company_doc.custom_street
    cbc_BuildingNumber = ET.SubElement(cac_PostalAddress, "cbc:BuildingNumber")
    cbc_BuildingNumber.text = str(company_doc.custom_build_no)
    cbc_PlotIdentification = ET.SubElement(cac_PostalAddress, "cbc:PlotIdentification")
    cbc_PlotIdentification.text =  company_doc.custom_plot_id_no
    cbc_CitySubdivisionName = ET.SubElement(cac_PostalAddress, "cbc:CitySubdivisionName")
    cbc_CitySubdivisionName.text = company_doc.custom_sub
    cbc_CityName = ET.SubElement(cac_PostalAddress, "cbc:CityName")
    cbc_CityName.text = company_doc.custom_city
    cbc_PostalZone = ET.SubElement(cac_PostalAddress, "cbc:PostalZone")
    cbc_PostalZone.text = str(company_doc.custom_pincode)
    cbc_CountrySubentity = ET.SubElement(cac_PostalAddress, "cbc:CountrySubentity")
    cbc_CountrySubentity.text = company_doc.custom_state
    cac_Country = ET.SubElement(cac_PostalAddress, "cac:Country")
    cbc_IdentificationCode = ET.SubElement(cac_Country, "cbc:IdentificationCode")
    cbc_IdentificationCode.text = company_doc.custom_country_name
    cac_PartyTaxScheme = ET.SubElement(cac_Party_1, "cac:PartyTaxScheme")
    cbc_CompanyID = ET.SubElement(cac_PartyTaxScheme, "cbc:CompanyID")
    cbc_CompanyID.text = company_doc.tax_id
    cac_TaxScheme = ET.SubElement(cac_PartyTaxScheme, "cac:TaxScheme")
    cbc_ID_3 = ET.SubElement(cac_TaxScheme, "cbc:ID")
    cbc_ID_3.text = "VAT"
    cac_PartyLegalEntity = ET.SubElement(cac_Party_1, "cac:PartyLegalEntity")
    cbc_RegistrationName = ET.SubElement(cac_PartyLegalEntity, "cbc:RegistrationName")
    cbc_RegistrationName.text = sales_invoice_doc.company
    return invoice

def customer_Data(invoice):
    customer_doc= frappe.get_doc("Customer",sales_invoice_doc.customer)
    cac_AccountingCustomerParty = ET.SubElement(invoice, "cac:AccountingCustomerParty")
    cac_Party_2 = ET.SubElement(cac_AccountingCustomerParty, "cac:Party")
    cac_PartyIdentification_1 = ET.SubElement(cac_Party_2, "cac:PartyIdentification")
    cbc_ID_4 = ET.SubElement(cac_PartyIdentification_1, "cbc:ID")
    cbc_ID_4.set("schemeID", "SAG")
    cbc_ID_4.text = customer_doc.custom_accounting_customer_id
    cac_PostalAddress_1 = ET.SubElement(cac_Party_2, "cac:PostalAddress")
    cbc_StreetName_1 = ET.SubElement(cac_PostalAddress_1, "cbc:StreetName")
    cbc_StreetName_1.text = customer_doc.custom_street
    cbc_BuildingNumber_1 = ET.SubElement(cac_PostalAddress_1, "cbc:BuildingNumber")
    cbc_BuildingNumber_1.text = str(customer_doc.custom_building_no)
    cbc_PlotIdentification_1 = ET.SubElement(cac_PostalAddress_1, "cbc:PlotIdentification")
    cbc_PlotIdentification_1.text = customer_doc.custom_plot_id_no
    cbc_CitySubdivisionName_1 = ET.SubElement(cac_PostalAddress_1, "cbc:CitySubdivisionName")
    cbc_CitySubdivisionName_1.text = customer_doc.custom_sub
    cbc_CityName_1 = ET.SubElement(cac_PostalAddress_1, "cbc:CityName")
    cbc_CityName_1.text = customer_doc.custom_city
    cbc_PostalZone_1 = ET.SubElement(cac_PostalAddress_1, "cbc:PostalZone")
    cbc_PostalZone_1.text = str(customer_doc.custom_pincode)
    cbc_CountrySubentity_1 = ET.SubElement(cac_PostalAddress_1, "cbc:CountrySubentity")
    cbc_CountrySubentity_1.text = customer_doc.custom_sub
    cac_Country_1 = ET.SubElement(cac_PostalAddress_1, "cac:Country")
    cbc_IdentificationCode_1 = ET.SubElement(cac_Country_1, "cbc:IdentificationCode")
    cbc_IdentificationCode_1.text = customer_doc.custom_country
    cac_PartyTaxScheme_1 = ET.SubElement(cac_Party_2, "cac:PartyTaxScheme")
    cac_TaxScheme_1 = ET.SubElement(cac_PartyTaxScheme_1, "cac:TaxScheme")
    cbc_ID_5 = ET.SubElement(cac_TaxScheme_1, "cbc:ID")
    cbc_ID_5.text = "VAT"
    cac_PartyLegalEntity_1 = ET.SubElement(cac_Party_2, "cac:PartyLegalEntity")
    cbc_RegistrationName_1 = ET.SubElement(cac_PartyLegalEntity_1, "cbc:RegistrationName")
    cbc_RegistrationName_1.text = sales_invoice_doc.customer
    return invoice

def delivery_And_PaymentMeans(invoice):
    cac_Delivery = ET.SubElement(invoice, "cac:Delivery")
    cbc_ActualDeliveryDate = ET.SubElement(cac_Delivery, "cbc:ActualDeliveryDate")
    cbc_ActualDeliveryDate.text = str(sales_invoice_doc.due_date)
    cac_PaymentMeans = ET.SubElement(invoice, "cac:PaymentMeans")
    cbc_PaymentMeansCode = ET.SubElement(cac_PaymentMeans, "cbc:PaymentMeansCode")
    cbc_PaymentMeansCode.text = str(sales_invoice_doc.custom_payment_code)
    return invoice

def tax_Data(invoice):
    cac_TaxTotal = ET.SubElement(invoice, "cac:TaxTotal")
    cbc_TaxAmount = ET.SubElement(cac_TaxTotal, "cbc:TaxAmount")
    cbc_TaxAmount.set("currencyID", sales_invoice_doc.currency) # SAR is given earlier directly
    cbc_TaxAmount.text =str( sales_invoice_doc.base_total_taxes_and_charges)
    cac_TaxSubtotal = ET.SubElement(cac_TaxTotal, "cac:TaxSubtotal")
    cbc_TaxableAmount = ET.SubElement(cac_TaxSubtotal, "cbc:TaxableAmount")
    cbc_TaxableAmount.set("currencyID", sales_invoice_doc.currency)
    cbc_TaxableAmount.text =str(sales_invoice_doc.base_net_total)
    cbc_TaxAmount_2 = ET.SubElement(cac_TaxSubtotal, "cbc:TaxAmount")
    cbc_TaxAmount_2.set("currencyID", sales_invoice_doc.currency)
    cbc_TaxAmount_2.text =  str(sales_invoice_doc.base_total_taxes_and_charges)
    cac_TaxCategory_1 = ET.SubElement(cac_TaxSubtotal, "cac:TaxCategory")
    cbc_ID_8 = ET.SubElement(cac_TaxCategory_1, "cbc:ID")
    cbc_ID_8.text = sales_invoice_doc.custom_taxcateg_id
    cbc_Percent_1 = ET.SubElement(cac_TaxCategory_1, "cbc:Percent")
    cbc_Percent_1.text = str(sales_invoice_doc.taxes[0].rate)
    cac_TaxScheme_3 = ET.SubElement(cac_TaxCategory_1, "cac:TaxScheme")
    cbc_ID_9 = ET.SubElement(cac_TaxScheme_3, "cbc:ID")
    cbc_ID_9.text = "VAT"
    cac_TaxTotal = ET.SubElement(invoice, "cac:TaxTotal")
    cbc_TaxAmount = ET.SubElement(cac_TaxTotal, "cbc:TaxAmount")
    cbc_TaxAmount.set("currencyID", sales_invoice_doc.currency)
    cbc_TaxAmount.text =str( sales_invoice_doc.base_total_taxes_and_charges)
    cac_LegalMonetaryTotal = ET.SubElement(invoice, "cac:LegalMonetaryTotal")
    cbc_LineExtensionAmount = ET.SubElement(cac_LegalMonetaryTotal, "cbc:LineExtensionAmount")
    cbc_LineExtensionAmount.set("currencyID", sales_invoice_doc.currency)
    cbc_LineExtensionAmount.text =  str(sales_invoice_doc.base_net_total)
    cbc_TaxExclusiveAmount = ET.SubElement(cac_LegalMonetaryTotal, "cbc:TaxExclusiveAmount")
    cbc_TaxExclusiveAmount.set("currencyID", sales_invoice_doc.currency)
    cbc_TaxExclusiveAmount.text = str(sales_invoice_doc.base_net_total)
    cbc_TaxInclusiveAmount = ET.SubElement(cac_LegalMonetaryTotal, "cbc:TaxInclusiveAmount")
    cbc_TaxInclusiveAmount.set("currencyID", sales_invoice_doc.currency)
    cbc_TaxInclusiveAmount.text = str(sales_invoice_doc.grand_total)
    cbc_AllowanceTotalAmount = ET.SubElement(cac_LegalMonetaryTotal, "cbc:AllowanceTotalAmount")
    cbc_AllowanceTotalAmount.set("currencyID", sales_invoice_doc.currency)
    cbc_AllowanceTotalAmount.text = str(sales_invoice_doc.base_change_amount)
    cbc_PayableAmount = ET.SubElement(cac_LegalMonetaryTotal, "cbc:PayableAmount")
    cbc_PayableAmount.set("currencyID", sales_invoice_doc.currency)
    cbc_PayableAmount.text = str(sales_invoice_doc.grand_total) 
    return invoice

def item_data(invoice):
    for single_item in sales_invoice_doc.items : 
        item_tax_amount,item_tax_percentage =  get_Tax_for_Item(sales_invoice_doc.taxes[0].item_wise_tax_detail,single_item.item_code)
        cac_InvoiceLine = ET.SubElement(invoice, "cac:InvoiceLine")
        cbc_ID_10 = ET.SubElement(cac_InvoiceLine, "cbc:ID")
        cbc_ID_10.text = str(single_item.idx)
        cbc_InvoicedQuantity = ET.SubElement(cac_InvoiceLine, "cbc:InvoicedQuantity")
        cbc_InvoicedQuantity.set("unitCode", str(single_item.uom))
        cbc_InvoicedQuantity.text = str(single_item.qty)
        cbc_LineExtensionAmount_1 = ET.SubElement(cac_InvoiceLine, "cbc:LineExtensionAmount")
        cbc_LineExtensionAmount_1.set("currencyID", sales_invoice_doc.currency)
        cbc_LineExtensionAmount_1.text=  str(single_item.amount)
        cac_TaxTotal_2 = ET.SubElement(cac_InvoiceLine, "cac:TaxTotal")
        cbc_TaxAmount_3 = ET.SubElement(cac_TaxTotal_2, "cbc:TaxAmount")
        cbc_TaxAmount_3.set("currencyID", sales_invoice_doc.currency)
        cbc_TaxAmount_3.text = str(item_tax_amount)
        cbc_RoundingAmount = ET.SubElement(cac_TaxTotal_2, "cbc:RoundingAmount")
        cbc_RoundingAmount.set("currencyID", sales_invoice_doc.currency)
        cbc_RoundingAmount.text=str(single_item.amount + item_tax_amount)
        cac_Item = ET.SubElement(cac_InvoiceLine, "cac:Item")
        cbc_Name = ET.SubElement(cac_Item, "cbc:Name")
        cbc_Name.text = single_item.item_code
        cac_ClassifiedTaxCategory = ET.SubElement(cac_Item, "cac:ClassifiedTaxCategory")
        cbc_ID_11 = ET.SubElement(cac_ClassifiedTaxCategory, "cbc:ID")
        cbc_ID_11.text = sales_invoice_doc.custom_item_character
        cbc_Percent_2 = ET.SubElement(cac_ClassifiedTaxCategory, "cbc:Percent")
        cbc_Percent_2.text =str(item_tax_percentage)
        cac_TaxScheme_4 = ET.SubElement(cac_ClassifiedTaxCategory, "cac:TaxScheme")
        cbc_ID_12 = ET.SubElement(cac_TaxScheme_4, "cbc:ID")
        cbc_ID_12.text = "VAT"
        cac_Price = ET.SubElement(cac_InvoiceLine, "cac:Price")
        cbc_PriceAmount = ET.SubElement(cac_Price, "cbc:PriceAmount")
        cbc_PriceAmount.set("currencyID", sales_invoice_doc.currency)
        cbc_PriceAmount.text =  str(single_item.price_list_rate)
    return invoice 

def xml_structuring(invoice):
            xml_declaration = "<?xml version='1.0' encoding='UTF-8'?>\n"
            tree = ET.ElementTree(invoice)
            with open(f"/opt/oxy/frappe-bench/sites/xml_files.xml", 'wb') as file:
                tree.write(file, encoding='utf-8', xml_declaration=True)
            with open(f"/opt/oxy/frappe-bench/sites/xml_files.xml", 'r') as file:
                xml_string = file.read()
            xml_dom = minidom.parseString(xml_string)
            pretty_xml_string = xml_dom.toprettyxml(indent="  ")  # You can specify the desired indentation level
            with open(f"/opt/oxy/frappe-bench/sites/finalzatcaxml.xml", 'w') as file:
                file.write(pretty_xml_string)

def encode_csr():
            with open("hellotaxpayer.csr", "r") as file_csr:
                get_csr = file_csr.read()
            get_csr = get_csr.strip()
            encoded_certificate = base64.b64encode(get_csr.encode("utf-8")).decode("utf-8")
            with open("encoded_csr.txt", "w") as file:
                file.write(encoded_certificate)
            # print("Encoded CSR saved to encoded_csr.txt")

def send_csr():       
            headers = {'accept': 'application/json',
                'OTP': '113753',
                'Accept-Version': 'V2',
                'Content-Type': 'application/json', }
            with open ("encoded_csr.txt" , "r") as read_file :        
                json_data = {
                    'csr': read_file.read(),}
            response = requests.post(
                'https://gw-fatoora.zatca.gov.sa/e-invoicing/developer-portal/compliance',
                headers=headers,
                json=json_data, )
            final_resp = json.dumps(response.json())
            with open("response_from_send_csr.json" , "w")as file : 
                file.write(final_resp)
            # print(response.json())
            data=json.loads(response.text)
            return data["binarySecurityToken"],  data["secret"]

def decoded_Binary_Security_Token():
            decoded_binary_security_token = ""
            with open('/opt/oxy/frappe-bench/sites/response_from_send_csr.json' , 'r') as json_file : 
                data = json.load(json_file)
                decoded_binary_security_token = base64.b64decode(data['binarySecurityToken'])
            json_file.close()
            return decoded_binary_security_token
            

def sign_xml_hash():
            xml_file = "/opt/oxy/frappe-bench/sites/finalzatcaxml.xml"
            tree = etree.parse(xml_file)
            tags_to_remove = ["//ext:UBLExtension", "//cbc:Signature", "//cbc:AdditionalDocumentReference[cbc:ID='QR']"]
            for tag in tags_to_remove:
                for element in tree.xpath(tag, namespaces={"ext": "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2",
                                                            "cbc": "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2" , 
                                                            'cac':"urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"}):
                    element.getparent().remove(element)
                    print('-------------')
            # Canonicalize the Invoice
            xml_str = etree.tostring(tree.getroot(), method="c14n", exclusive=False, with_comments=False)
            invoice_hash = hashlib.sha256(xml_str).digest()
            print("invoice hash is",invoice_hash)
            encoded_invoice_hash = base64.b64encode(invoice_hash).decode()
            print("Encoded Invoice Hash:", encoded_invoice_hash)
            return invoice_hash ,encoded_invoice_hash

def signature_Function(invoice_hash,decoded_binary_security_token):
            with open("/opt/oxy/frappe-bench/sites/helloprikey.pem", "rb") as key_file:
                private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
                signature = private_key.sign(invoice_hash, ec.ECDSA(hashes.SHA256()))
                encoded_signature = base64.b64encode(signature).decode()
            encoded_certificate_hash = ""
            certificate_hash = hashlib.sha256(decoded_binary_security_token).digest()
            encoded_certificate_hash = base64.b64encode(certificate_hash).decode()
            print("Encoded Certificate Hash:", encoded_certificate_hash)
            return encoded_signature,encoded_certificate_hash

def signxml_modify(encoded_certificate_hash):
            original_invoice_xml = etree.parse('/opt/oxy/frappe-bench/sites/finalzatcaxml.xml')
            root = original_invoice_xml.getroot()
            namespaces = {
            'ext': 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2',
            'sig': 'urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2',
            'sac':"urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2", 
            'xades': 'http://uri.etsi.org/01903/v1.3.2#',
            'ds': 'http://www.w3.org/2000/09/xmldsig#'}
            ubl_extensions_xpath = "//*[local-name()='Invoice']//*[local-name()='UBLExtensions']"
            qr_xpath = "//*[local-name()='AdditionalDocumentReference'][cbc:ID[normalize-space(text()) = 'QR']]"
            signature_xpath = "//*[local-name()='Invoice']//*[local-name()='Signature']"
            xpath_dv = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningCertificate/xades:Cert/xades:CertDigest/ds:DigestValue")
            xpath_signTime = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningTime")
            xpath_issuerName = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningCertificate/xades:Cert/xades:IssuerSerial/ds:X509IssuerName")
            xpath_serialNum = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties//xades:SignedSignatureProperties/xades:SigningCertificate/xades:Cert/xades:IssuerSerial/ds:X509SerialNumber")
            element_dv = root.find(xpath_dv, namespaces)
            element_st = root.find(xpath_signTime, namespaces)
            element_in = root.find(xpath_issuerName, namespaces)
            element_sn = root.find(xpath_serialNum, namespaces)
            element_dv.text = (encoded_certificate_hash)
            element_st.text = str(datetime.utcnow().isoformat())
            element_in.text = 'E=husna@gmail.com, CN=ERP, OU=ERPGULF, O=WE, L=ER, ST=RIYAD, C=SA'
            element_sn.text = '294932932413855994052542058908583632493074097051'
            with open("/opt/oxy/frappe-bench/sites/after_step_4.xml", 'wb') as file:
                original_invoice_xml.write(file,encoding='utf-8',xml_declaration=True,)
            return original_invoice_xml,namespaces

def generate_Signed_Properties_Hash(original_invoice_xml,namespaces):
            xml_from_step_4 = etree.parse('/opt/oxy/frappe-bench/sites/after_step_4.xml')
            root2 = original_invoice_xml.getroot()
            xpath_signedProp = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties")
            signed_prop_tag = root2.find(xpath_signedProp , namespaces)
            signed_properties_xml = ET.tostring(signed_prop_tag , encoding='utf-8').decode().replace(" ", "")
            signed_properties_hash = hashlib.sha256(signed_properties_xml.encode()).digest()
            signed_properties_hex = signed_properties_hash.hex()
            signed_properties_base64 = base64.b64encode(bytes.fromhex(signed_properties_hex)).decode()
            return signed_properties_base64

def populate_The_UBL_Extensions_Output():
            updated_invoice_xml = etree.parse('/opt/oxy/frappe-bench/sites/after_step_4.xml')
            root3 = updated_invoice_xml.getroot()
            xpath_signvalue = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:SignatureValue")
            xpath_x509certi = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate")
            xpath_digvalue = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:SignedInfo/ds:Reference[@URI='#xadesSignedProperties']/ds:DigestValue")
            xpath_digvalue2 = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:SignedInfo/ds:Reference[@Id='invoiceSignedData']/ds:DigestValue")
            signValue6 = root3.find(xpath_signvalue , namespaces)
            x509Certificate6 = root3.find(xpath_x509certi , namespaces)
            digestvalue6 = root3.find(xpath_digvalue , namespaces)
            digestvalue6_2 = root3.find(xpath_digvalue2 , namespaces)
            signValue6.text = (encoded_signature)
            x509Certificate6.text = (decoded_binary_security_token)
            digestvalue6.text = (signed_properties_base64)
            digestvalue6_2.text =(encoded_invoice_hash)
            with open("/opt/oxy/frappe-bench/sites/final_xml_after_sign.xml", 'wb') as file:
                updated_invoice_xml.write(file,encoding='utf-8',xml_declaration=True,)
            return encoded_invoice_hash

# def get_signed_xml_invoice_for_clearance():
#             try:
#                 signedXmlFilePath="/opt/oxy/frappe-bench/sites/final_xml_after_sign.xml"
#                 xmlTree = ET.ElementTree(file=signedXmlFilePath)
#                 namespaces1 = {
#                     'ext': 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2',
#                     'sig': 'urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2',
#                     'sac': 'urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2',
#                     'ds': 'http://www.w3.org/2000/09/xmldsig#',
#                 }
#                 xpath_expression = (
#                     ".//ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/"
#                     "sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/"
#                     "ds:SignedInfo/ds:Reference[1]/ds:DigestValue"
#                 )
#                 element =xmlTree.find(xpath_expression, namespaces=namespaces1)
#                 if element is not None:
#                     sbDigestValue = element.text
#                 else:
#                     print("Element not found at the specified path.")
#                     sys.exit()
#                 return sbDigestValue
#             except Exception as e:
#                 print(f"Error: {str(e)}")
#                 sys.exit()

def generate_tlv_xml():
                sellerName = "Firoz Ashraf"
                vatNumber = "1234567891"
                timeStamp = "2021-11-17 08:30:00"
                invoiceTotal = "100.00"
                vatTotal = "15.00"
                tag = 1
                tlv_data = []
                tlv_data.append(bytes([tag]))
                tlv_data.append(sellerName.encode('utf-8'))
                tag += 1
                tlv_data.append(bytes([tag]))
                tlv_data.append(vatNumber.encode('utf-8'))
                tag += 1
                tlv_data.append(bytes([tag]))
                tlv_data.append(timeStamp.encode('utf-8'))
                tag += 1
                tlv_data.append(bytes([tag]))
                tlv_data.append(invoiceTotal.encode('utf-8')) 
                tag += 1
                tlv_data.append(bytes([tag]))
                tlv_data.append(vatTotal.encode('utf-8'))
                sbDigestValue = encoded_invoice_hash
                tag = 6
                tlv_data.append(bytes([tag]))
                tlv_data.append(len(sbDigestValue).to_bytes(1, byteorder='big'))
                tlv_data.append(sbDigestValue.encode('utf-8'))
                tlv_encoded = base64.b64encode(b''.join(tlv_data)).decode('utf-8')
                return tlv_encoded

def add_Qr_toXml(tlv_encoded):
                signedXmlFilePath="/opt/oxy/frappe-bench/sites/final_xml_after_sign.xml"
                tree = ET.parse(signedXmlFilePath)
                root = tree.getroot()
                namespace = {
                    'cac': 'urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2',
                    'cbc': 'urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2', }
                # Find the element to be replaced
                target_element = root.find(".//cac:AdditionalDocumentReference[cbc:ID='QR']/cac:Attachment/cbc:EmbeddedDocumentBinaryObject", namespaces=namespace)
                # Replace the text content with your TLV data variable
                target_element.text = generate_tlv_xml()
                # print(target_element.text)
                tree.write("/opt/oxy/frappe-bench/sites/signedXML_withQR123.xml", xml_declaration=True, encoding='utf-8')


def generate_hash(xmlfile_name):
                    # Generate hash using Javs SDK - Farook
                command_generate_hash = 'fatoora -generateHash -invoice ' + xmlfile_name
                try:
                        result = subprocess.run(command_generate_hash, shell=True, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        pattern = r'INVOICE HASH = (.+)'
                        match = re.search(pattern, result.stdout)
                        if match:
                            hash_value = match.group(1)
                            return(hash_value)
                        else:
                            return("Hash value not found in the log entry.")
                except subprocess.CalledProcessError as e:
                        return("Error:")
                        return(e.stderr)
                
def validate_invoice(xmlfile_name):
                    # Validate the invoice - Using JAVA SDK Farook
                command_generate_hash = 'fatoora -validate -invoice ' + xmlfile_name
                try:
                        result = subprocess.run(command_generate_hash, shell=True, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        pattern = pattern_global_result = re.compile(r'\*\*\* GLOBAL VALIDATION RESULT = (\w+)')
                        pattern_global_result = re.compile(r'\*\*\* GLOBAL VALIDATION RESULT = (\w+)')
                        # Extract global validation result
                        global_result_match = pattern_global_result.search(result.stdout)
                        global_result = global_result_match.group(1) if global_result_match else None
                        # Check if the global validation result is PASSED or FAILED
                        global_validation_result = 'PASSED' if global_result == 'PASSED' else 'FAILED'
                        # Print the global validation result
                        if  global_validation_result =='FAILED' :
                                    print (result.stdout)
                        else :
                                    global_validation_result
                except subprocess.CalledProcessError as e:
                        return("Error:")
                        return(e.stderr)
                
invoice_file = "/opt/oxy/frappe-bench/sites/signedXML_withQR123.xml"
print(generate_hash(invoice_file))
print(validate_invoice(invoice_file))

def send_invoice_for_clearance_normal(uuid1):
                    signedXmlFilePath = "/opt/oxy/frappe-bench/sites/signedXML_withQR123.xml"
                    token,secret = send_csr()
                    with open(signedXmlFilePath, "r") as file:
                        xml = file.read().lstrip()
                        base64_encoded = base64.b64encode(xml.encode("utf-8"))
                        base64_decoded = base64_encoded.decode("utf-8")
                        # print(base64_decoded)
                    url = "https://gw-fatoora.zatca.gov.sa/e-invoicing/developer-portal/compliance/invoices"
                    payload = json.dumps({
                    "invoiceHash":generate_hash(invoice_file),
                    "uuid": uuid1,
                    "invoice": base64_decoded})
                    headers = { 
                        'accept': 'application/json',
                        'Accept-Language': 'en',
                        'Accept-Version': 'V2',
                        'Authorization': "Basic VFVsSlJERnFRME5CTTNsblFYZEpRa0ZuU1ZSaWQwRkJaVFJUYUhOMmVXNDNNREo1VUhkQlFrRkJRamRvUkVGTFFtZG5jV2hyYWs5UVVWRkVRV3BDYWsxU1ZYZEZkMWxMUTFwSmJXbGFVSGxNUjFGQ1IxSlpSbUpIT1dwWlYzZDRSWHBCVWtKbmIwcHJhV0ZLYXk5SmMxcEJSVnBHWjA1dVlqTlplRVo2UVZaQ1oyOUthMmxoU21zdlNYTmFRVVZhUm1ka2JHVklVbTVaV0hBd1RWSjNkMGRuV1VSV1VWRkVSWGhPVlZVeGNFWlRWVFZYVkRCc1JGSlRNVlJrVjBwRVVWTXdlRTFDTkZoRVZFbDVUVVJaZUUxNlJURk5la1V3VG14dldFUlVTVEJOUkZsNFRXcEZNVTE2UlRCT2JHOTNVMVJGVEUxQmEwZEJNVlZGUW1oTlExVXdSWGhFYWtGTlFtZE9Wa0pCYjFSQ1YwWnVZVmQ0YkUxU1dYZEdRVmxFVmxGUlRFVjNNVzlaV0d4b1NVaHNhRm95YUhSaU0xWjVUVkpKZDBWQldVUldVVkZFUlhkcmVFMXFZM1ZOUXpSM1RHcEZkMVpxUVZGQ1oyTnhhR3RxVDFCUlNVSkNaMVZ5WjFGUlFVTm5Ua05CUVZSVVFVczViSEpVVm10dk9YSnJjVFphV1dOak9VaEVVbHBRTkdJNVV6UjZRVFJMYlRkWldFb3JjMjVVVm1oTWEzcFZNRWh6YlZOWU9WVnVPR3BFYUZKVVQwaEVTMkZtZERoREwzVjFWVms1TXpSMmRVMU9ielJKUTB0cVEwTkJhVmwzWjFselIwRXhWV1JGVVZOQ1ozcERRbWRMVWl0TlNIZDRTRlJCWWtKblRsWkNRVkZOUmtSRmRHRkhSalZaV0hkNVRGUkplazVJZDNwTVZFVjRUV3BOZWsxU09IZElVVmxMUTFwSmJXbGFVSGxNUjFGQ1FWRjNVRTE2VFhoTlZGbDVUMFJaTlU1RVFYZE5SRUY2VFZFd2QwTjNXVVJXVVZGTlJFRlJlRTFVUVhkTlVrVjNSSGRaUkZaUlVXRkVRV2hoV1ZoU2FsbFRRWGhOYWtWWlRVSlpSMEV4VlVWRWQzZFFVbTA1ZGxwRFFrTmtXRTU2WVZjMWJHTXpUWHBOUWpCSFFURlZaRVJuVVZkQ1FsTm5iVWxYUkRaaVVHWmlZa3RyYlZSM1QwcFNXSFpKWWtnNVNHcEJaa0puVGxaSVUwMUZSMFJCVjJkQ1VqSlpTWG8zUW5GRGMxb3hZekZ1WXl0aGNrdGpjbTFVVnpGTWVrSlBRbWRPVmtoU09FVlNla0pHVFVWUFoxRmhRUzlvYWpGdlpFaFNkMDlwT0haa1NFNHdXVE5LYzB4dWNHaGtSMDVvVEcxa2RtUnBOWHBaVXpsRVdsaEtNRkpYTlhsaU1uaHpUREZTVkZkclZrcFViRnBRVTFWT1JreFdUakZaYTA1Q1RGUkZkVmt6U25OTlNVZDBRbWRuY2tKblJVWkNVV05DUVZGVFFtOUVRMEp1VkVKMVFtZG5ja0puUlVaQ1VXTjNRVmxhYVdGSVVqQmpSRzkyVEROU2VtUkhUbmxpUXpVMldWaFNhbGxUTlc1aU0xbDFZekpGZGxFeVZubGtSVloxWTIwNWMySkRPVlZWTVhCR1lWYzFNbUl5YkdwYVZrNUVVVlJGZFZwWWFEQmFNa1kyWkVNMWJtSXpXWFZpUnpscVdWZDRabFpHVG1GU1ZXeFBWbXM1U2xFd1ZYUlZNMVpwVVRCRmRFMVRaM2hMVXpWcVkyNVJkMHQzV1VsTGQxbENRbEZWU0UxQlIwZElNbWd3WkVoQk5reDVPVEJqTTFKcVkyMTNkV1Z0UmpCWk1rVjFXakk1TWt4dVRtaE1NamxxWXpOQmQwUm5XVVJXVWpCUVFWRklMMEpCVVVSQloyVkJUVUl3UjBFeFZXUktVVkZYVFVKUlIwTkRjMGRCVVZWR1FuZE5RMEpuWjNKQ1owVkdRbEZqUkVGNlFXNUNaMnR5UW1kRlJVRlpTVE5HVVc5RlIycEJXVTFCYjBkRFEzTkhRVkZWUmtKM1RVTk5RVzlIUTBOelIwRlJWVVpDZDAxRVRVRnZSME5EY1VkVFRUUTVRa0ZOUTBFd1owRk5SVlZEU1ZGRVQxQXdaakJFY21oblpVUlVjbFpNZEVwMU9HeFhhelJJU25SbFkyWTFabVpsVWt4blpVUTRZMlZWWjBsblpFSkNUakl4U1RNM2FYTk5PVlZ0VTFGbE9IaFNjRWh1ZDA5NFNXYzNkMDR6V1RKMlZIQnpVR2hhU1QwPTpFcGo2OUdoOFRNTXpZZktsdEx2MW9tWktyaWUwc1A2TEF2YW1iUUZIVGd3PQ==",
                        'Content-Type': 'application/json'}  
                    response = requests.request("POST", url, headers=headers, data=payload)
                    print(response.text)

invoice= xml_tags()
invoice,uuid1=salesinvoice_data(invoice)
invoice=additional_Reference(invoice)
invoice=company_Data(invoice)
invoice=customer_Data(invoice)
invoice=delivery_And_PaymentMeans(invoice)
invoice=tax_Data(invoice)
invoice=item_data(invoice)
pretty_xml_string=xml_structuring(invoice)
send_csr()
decoded_binary_security_token=decoded_Binary_Security_Token()
invoice_hash,encoded_invoice_hash=sign_xml_hash()
encoded_signature,encoded_certificate_hash=signature_Function(invoice_hash,decoded_binary_security_token)
original_invoice_xml,namespaces=signxml_modify(encoded_certificate_hash)
signed_properties_base64=generate_Signed_Properties_Hash(original_invoice_xml,namespaces)
sbXml=populate_The_UBL_Extensions_Output()
tlv_encoded= generate_tlv_xml()
add_Qr_toXml(tlv_encoded)
send_invoice_for_clearance_normal(uuid1)