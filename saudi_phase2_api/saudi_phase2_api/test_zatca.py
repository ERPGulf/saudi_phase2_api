import frappe
frappe.init(site="husna.erpgulf.com")
frappe.connect()
import requests    
import pyqrcode
import os
from frappe.utils import cstr, flt
import uuid
from pickle import FALSE
import time
from frappe.utils.data import add_to_date, get_time, getdate
from base64 import b64encode
import base64
import json
import hashlib
from fatoora import Fatoora
from frappe.utils.file_manager import remove_file
from OpenSSL import crypto
from subprocess import call
def create_Csr():
    cmd = "openssl ecparam -name secp256k1 -genkey -noout -out privatekey3.pem"
    decrypted1 = call(cmd, shell=True) 
    cmd1="openssl ec -in privatekey3.pem -pubout -conv_form compressed -out publickey3.pem"
    decrypted2 = call(cmd1, shell=True) 
    cmd2="openssl req -new -sha256 -key privatekey3.pem -extensions v3_req -config /opt/oxy/frappe-bench/apps/saudi_phase2_api/saudi_phase2_api/saudi_phase2_api/csrconfig.txt -out taxpayer3.csr" 
    decrypted3 = call(cmd2, shell=True)  
    cmd3="openssl base64 -in taxpayer3.csr -out taxpayerCSRbase64Encoded3.txt" 
    decrypted4 = call(cmd3, shell=True) 
    with open(r'taxpayerCSRbase64Encoded3.txt', 'r') as file:
        data = file.read()
        data = data.replace("\n","")
        data = data.replace("\r","")
    with open(r'taxpayerCSRbase64Encoded3.txt', 'w') as file:
        file.write(data)
        print("done")
    return data
def compliance_API_call(csr):
    # print("inside compliance api call")
    # print(csr)
    # body_string =  "csr:" + csr
    #print(body_string) 
    url = "https://gw-fatoora.zatca.gov.sa/e-invoicing/developer-portal/compliance"
    payload = json.dumps({
        "csr": csr
    })
    headers = {
        'accept': 'application/json',
        'OTP': '123345',
        'Accept-Version': 'V2',
        'Content-Type': 'application/json',
        'Cookie': 'TS0106293e=0132a679c00d8c15498885a6fddfa94c457591c8f01fd4536cfd0956e0f94498f777d476fd1f4ef7a8f75b2e6187d147372e659a4d'
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    print(response.text)
    # return response
#creating csr
csr = create_Csr()
# print("before printing csr")
# print(csr)
#passing the CSR to API call.
compliance_API_call(csr)
def get_vat_amount(doc):
	vat_settings = frappe.db.get_value("KSA VAT Setting", {"company": doc.company})
	vat_accounts = []
	vat_amount = 0

	if vat_settings:
		vat_settings_doc = frappe.get_cached_doc("KSA VAT Setting", vat_settings)
		for row in vat_settings_doc.get("ksa_vat_sales_accounts"):
			vat_accounts.append(row.account)

	for tax in doc.get("taxes"):
		if tax.account_head in vat_accounts:
			vat_amount += tax.tax_amount

	return vat_amount

def get_invoice_summary(items, taxes):
    summary_data = frappe._dict()
    for tax in taxes:
        # Include only VAT charges.
        if tax.charge_type == "Actual":
            continue
        # Charges to appear as items in the e-invoice.
        if tax.charge_type in ["On Previous Row Total", "On Previous Row Amount"]:
            reference_row = next(
                (row for row in taxes if row.idx == int(tax.row_id or 0)), None)
            if reference_row:
                items.append(
                    frappe._dict(
                        idx=len(items) + 1,
                        item_code=reference_row.description,
                        item_name=reference_row.description,
                        description=reference_row.description,
                        rate=reference_row.tax_amount,
                        qty=1.0,
                        amount=reference_row.tax_amount,
                        stock_uom=frappe.db.get_single_value(
                            "Stock Settings", "stock_uom") or _("Nos"),
                        tax_rate=tax.rate,
                        tax_amount=(reference_row.tax_amount * tax.rate) / 100,
                        net_amount=reference_row.tax_amount,
                        taxable_amount=reference_row.tax_amount,
                        item_tax_rate={tax.account_head: tax.rate},
                        charges=True,
                    )
                )
        # Check item tax rates if tax rate is zero.
        if tax.rate == 0:
            for item in items:
                item_tax_rate = item.item_tax_rate
                if isinstance(item.item_tax_rate, str):
                    item_tax_rate = json.loads(item.item_tax_rate)

                if item_tax_rate and tax.account_head in item_tax_rate:
                    key = cstr(item_tax_rate[tax.account_head])
                    if key not in summary_data:
                        summary_data.setdefault(
                            key,
                            {
                                "tax_amount": 0.0,
                                "taxable_amount": 0.0,
                                "tax_exemption_reason": "",
                                "tax_exemption_law": "",
                            },
                        )
                    summary_data[key]["tax_amount"] += tax.tax_amount
                    summary_data[key]["taxable_amount"] += item.net_amount
                    if key == "0.0":
                        summary_data[key]["tax_exemption_reason"] = tax.tax_exemption_reason
                        summary_data[key]["tax_exemption_law"] = tax.tax_exemption_law

            if summary_data.get("0.0") and tax.charge_type in [
                    "On Previous Row Total",
                    "On Previous Row Amount",
            ]:
                summary_data[key]["taxable_amount"] = tax.total
            if summary_data == {}:  # Implies that Zero VAT has not been set on any item.
                summary_data.setdefault(
                    "0.0",
                    {
                        "tax_amount": 0.0,
                        "taxable_amount": tax.total,
                        "tax_exemption_reason": tax.tax_exemption_reason,
                        "tax_exemption_law": tax.tax_exemption_law,
                    },
                )
        else:
            item_wise_tax_detail = json.loads(tax.item_wise_tax_detail)
            for rate_item in [
                    tax_item for tax_item in item_wise_tax_detail.items() if tax_item[1][0] == tax.rate
            ]:
                key = cstr(tax.rate)
                if not summary_data.get(key):
                    summary_data.setdefault(
                        key, {"tax_amount": 0.0, "taxable_amount": 0.0})
                summary_data[key]["tax_amount"] += rate_item[1][1]
                summary_data[key]["taxable_amount"] += sum(
                    [item.net_amount for item in items if item.item_code == rate_item[0]]
                )
            for item in items:
                key = cstr(tax.rate)
                if item.get("charges"):
                    if not summary_data.get(key):
                        summary_data.setdefault(key, {"taxable_amount": 0.0})
                    summary_data[key]["taxable_amount"] += item.taxable_amount
    return summary_data
def get_unamended_name(doc):
    attributes = ["naming_series", "amended_from"]
    for attribute in attributes:
        if not hasattr(doc, attribute):
            return doc.name
    if doc.amended_from:
        return "-".join(doc.name.split("-")[:-1])
    else:
        return doc.name
def prepare_invoice(invoice, progressive_number):
    print("before call api")
    # set company information
    company = frappe.get_doc("Company", invoice.company)
    #print(company)
    # load_tax_itemised = update_itemised_tax_data()
    invoice.progressive_number = progressive_number
    invoice.unamended_name = get_unamended_name(invoice)
    invoice.company_data = company
    print(invoice.progressive_number)
    print(invoice.unamended_name) 
    print(invoice.company_data)   
    #everyting ok untill here.
    #company_address = frappe.get_doc("Address", invoice.company_address)
    company_address = "Barwa Tower C-Ring Road Doha"
    print(company_address)
    invoice.company_address_data = company_address
    print(invoice.company_address_data)

    # Set invoice type
    # if not invoice.type_of_document:
    #     if invoice.is_return and invoice.return_against:
    #         invoice.type_of_document = "TD04"  # Credit Note (Nota di Credito)
    #         invoice.return_against_unamended = get_unamended_name(
    #             frappe.get_doc("Sales Invoice", invoice.return_against)
    #         )
    #     else:
    #         invoice.type_of_document = "TD01"  # Sales Invoice (Fattura)

    # set customer information
    invoice.customer_data = frappe.get_doc("Customer", invoice.customer)
    print(invoice.customer_data)
    #customer_address = frappe.get_doc("Address", invoice.customer_address)
    customer_address= "XXXXXXXX Meladi PO "
    print( " Customer _address " + customer_address)
    invoice.customer_address_data = customer_address
   
    # if invoice.shipping_address_name:
    #     invoice.shipping_address_data = frappe.get_doc(
    #         "Address", invoice.shipping_address_name)
    invoice.shipping_address_data= "rose street "  
    # if invoice.customer_data.is_public_administration:
    #     invoice.transmission_format_code = "FPA12"
    # else:
    #     invoice.transmission_format_code = "FPR12"
    invoice.e_invoice_items = [item for item in invoice.items]
    print(invoice.e_invoice_items)
    tax_data = get_invoice_summary(invoice.e_invoice_items, invoice.taxes)
    print(tax_data)
    invoice.tax_data = tax_data
    # Check if stamp duty (Bollo) of 2 EUR exists.
    stamp_duty_charge_row = next(
        (tax for tax in invoice.taxes if tax.charge_type ==
         "Actual" and tax.tax_amount == 2.0), None
    )
    print(stamp_duty_charge_row)
    # if stamp_duty_charge_row:
    #     invoice.stamp_duty = stamp_duty_charge_row.tax_amount
    # print(invoice.stamp_duty)
    invoice.stamp_duty= 0
    for item in invoice.e_invoice_items:
        if item.item_tax_rate == 0.0 and item.tax_amount == 0.0 and tax_data.get("0.0"):
            item.tax_exemption_reason = tax_data["0.0"]["tax_exemption_reason"]
    item.tax_exemption_reason =""
    customer_po_data = {}
    if invoice.po_no and invoice.po_date and invoice.po_no not in customer_po_data:
        customer_po_data[invoice.po_no] = invoice.po_date
    invoice.customer_po_data = customer_po_data
    print(invoice.customer_po_data)
    seller_name = frappe.db.get_value("Company", invoice.company, "name")
    # tax_id = frappe.db.get_value("Company", invoice.company, "tax_id")
    tax_id = "22253533555"
    print(tax_id)
    posting_date = getdate(invoice.posting_date)
    print(posting_date)  
    time = get_time(invoice.posting_time)
    print(time)
    seconds = time.hour * 60 * 60 + time.minute * 60 + time.second   
    time_stamp = add_to_date(posting_date, seconds=seconds)
    time_stamp = time_stamp.strftime("%Y-%m-%dT%H:%M:%SZ")
    print(time_stamp)
    invoice_amount = str(invoice.grand_total)
    print(invoice_amount)
    vat_amount = str(get_vat_amount(invoice))
    print(vat_amount)
    fatoora_obj = Fatoora(
    seller_name=seller_name,
    tax_number=tax_id, 
    invoice_date=time_stamp, 
    total_amount=invoice_amount, 
    tax_amount= vat_amount,
)
    print(fatoora_obj)
    invoice.qr_code =fatoora_obj.base64
    print(invoice.qr_code)
    invoice.uuid = uuid.uuid1()
    uuid1=invoice.uuid
    print(uuid1)
    # print(invoice.uuid)
    # settings = frappe.get_doc('Hash')
    settings = '12346'
    print(settings)
    invoice.pih = '123'
    print(invoice.pih)
    return invoice ,uuid1

# def get_e_invoice_attachments(invoices):
# 	if not isinstance(invoices, list):
# 		if not invoices.company_tax_id:
# 			return
# 		invoices = [invoices]
# 	tax_id_map = {
# 		invoice.name: (
# 			invoice.company_tax_id
# 			if invoice.company_tax_id.startswith("SA")
# 			else "SA" + invoice.company_tax_id
# 		)
# 		for invoice in invoices
# 	}
# 	attachments = frappe.get_all(
# 		"File",
# 		fields=("name", "file_name", "attached_to_name", "is_private"),
# 		filters={"attached_to_name": ("in", tax_id_map), "attached_to_doctype": "Sales Invoice"},
# 	)
    
# 	out = []
# 	for attachment in attachments:
# 		if (
# 			attachment.file_name
# 			and attachment.file_name.endswith(".xml")
# 			and attachment.file_name.startswith(tax_id_map.get(attachment.attached_to_name))
# 		):
# 			out.append(attachment)

# def get_progressive_name_and_number(doc, replace=False):
# 	if replace:
# 		for attachment in get_e_invoice_attachments(doc):
# 			remove_file(attachment.name, attached_to_doctype=doc.doctype, attached_to_name=doc.name)
# 			filename = attachment.file_name.split(".xml")[0]
# 			return filename, filename.split("_")[1]
# 	company_tax_id = (
# 		doc.company_tax_id if doc.company_tax_id.startswith("SA") else "SA" + doc.company_tax_id
# 	)
# 	progressive_name = frappe.model.naming.make_autoname(company_tax_id + "_.#####")
# 	progressive_number = progressive_name.split("_")[1]
# 	return progressive_name, progressive_number

def prepare_and_attach_invoice(doc,replace=False):
    # progressive_name, progressive_number = get_progressive_name_and_number(doc, replace)
    progressive_name ="Pro Name"
    progressive_number ="Pro Number"
    invoice = prepare_invoice(doc, progressive_number)
    print(invoice)
    item_meta = frappe.get_meta("Sales Invoice Item")
    print(item_meta)
    print(type(item_meta))
    invoice_xml = frappe.render_template(
        "saudi_phase2_api/saudi_phase2_api/e_test.xml",
        context={"doc": invoice, "item_meta": item_meta},
        is_path=True,
    )
    invoice_xml = invoice_xml.replace("&", "&amp;")
    print(invoice_xml)
    # invoice_content = invoice_xml
    # print(invoice_content)
    # return "something"
    xml_filename = progressive_name + ".xml"
    print(xml_filename)
    hash_name = progressive_name + ".txt" 
    file = frappe.get_doc(
        {
            "doctype": "File",
            "file_name": xml_filename,
            "attached_to_doctype": doc.doctype,
            "attached_to_name": doc.name,
            "content": invoice_xml,
        }
    )
    file.save()
    print(file)
    
    company_tax_id = doc.company_tax_id
    print(company_tax_id)
    
    attachments = frappe.get_all(
        "File",
        fields=("name", "file_name", "attached_to_name", "is_private"),
        filters={"file_name": xml_filename,
                 "attached_to_doctype": "Sales Invoice",
                 "attached_to_name": doc.name,},
    )
    print(attachments)
    # return invoice_content
    return file
    
def compliance_Invoice_API_Call(invoice):
    # invoice, uuid_value = prepare_and_attach_invoice(doc, replace=False)
    xml_file= prepare_and_attach_invoice(doc,replace=False)
    print(xml_file)
    
    with open(xml_file, 'r') as file:
        data1 = file.read()
        arr1 = bytes(data1, "utf-8")
        base64_encoded_data1 = base64.b64encode(arr1)
        base64_message1 = base64_encoded_data1.decode('utf-8')
        data = base64_message1.replace("\n","")
        data = base64_message1.replace("\r","")
        # data = base64.b64encode(xml_file.encode('utf-8')).decode('utf-8')
    with open(r'base64xml.txt', 'w') as file:
        # Writing the replaced data in our
        # text file
        file.write(data)
        print(type(data))
    invoice,uuid1 = prepare_invoice(invoice, "123")
    url = "https://gw-fatoora.zatca.gov.sa/e-invoicing/developer-portal/compliance/invoices"
    payload = json.dumps({
        "invoiceHash": "",
        "uuid":  str(uuid.uuid4()),
        "invoice":data
        })
    headers = {
        'accept': 'application/json',
        'Accept-Language': 'en',
        'Accept-Version': 'V2',
        'Authorization': 'Basic VFVsSlEwUkVRME5CWWt0blFYZEpRa0ZuU1VkQldYSXJhbm8wWVUxQmIwZERRM0ZIVTAwME9VSkJUVU5OUWxWNFJYcEJVa0puVGxaQ1FVMU5RMjFXU21KdVduWmhWMDV3WW0xamQwaG9ZMDVOYWsxNFRVUkJNVTFFV1hwUFJFMTNWMmhqVGsxcVozaE5SRUV3VFdwRmQwMUVRWGRYYWtKTlRWRnpkME5SV1VSV1VWRkhSWGRLVkZGVVJWWk5RazFIUVRGVlJVTjNkMDFWYld3MVdWZFJaMUZ1U21oaWJVNXZUVkpCZDBSbldVUldVVkZMUkVGa1JHSXlOVEJpTTA1MlRWSlJkMFZuV1VSV1VWRkVSRUYwUmxGVVJYbE5lbEV4VG1wak5FOVVRbGROUWtGSFFubHhSMU5OTkRsQlowVkhRbE4xUWtKQlFVdEJNRWxCUWt0NVV6QlJUVFJCVDJkTVRESkNaMU5RTkdsWlRGSXlWa2czU1RkSFJXOVJPR295Y1doUmNrSk9TRU5DUmxSYVdrMDRkVzV0TkZwUFNGSmFjRUpxVVRsRVdGQnRPR1JIV0RNMGNrSTVUVU5KVWtocE1Ia3JhbWRpYTNkbllsbDNSRUZaUkZaU01GUkJVVWd2UWtGSmQwRkVRMEp3VVZsRVZsSXdVa0pKUjJSTlNVZGhjRWxIV0UxSlIxVk5WSE4zVDFGWlJGWlJVVVZFUkVsNFRGWlNWRlpJZDNsTVZsSlVWa2gzZWt4WFZtdE5ha3B0VFZkUk5FeFhWVEpaVkVsMFRWUkZlRTlETURWWmFsVTBURmRSTlZsVWFHMU5WRVpzVGtSUk1WcHFSV1pOUWpCSFEyZHRVMHB2YlZRNGFYaHJRVkZGVFVSNlRYaE5SRVY1VFdwTk5VMTZWWGROUkVGM1RYcEZUazFCYzBkQk1WVkZSRUYzUlUxVVJYZE5SRVZUVFVKQlIwRXhWVVZIWjNkS1ZGaHNRbHBIVW5sYVdFNTZUVkpGZDBSM1dVUldVVkZRUkVGb1NtSnRVakZqTTFKNVpWUkJTMEpuWjNGb2EycFBVRkZSUkVGblRrbEJSRUpHUVdsQ0syRTNiM2xLYldGa2NYRjBSbGgwZVZKMGFHMTNielk1ZWxaNFZtSjVSbHBuVUZwNmMwUlVTamxoWjBsb1FVcDVWV1pJTXpScVlXaDRiR0UxVGtJMmFWbHhTWGxUT1VWME5FRXlWV3d2TVVoM1VXYzNURVZ5UmtRPToyWmhjTmpQV2FUK09LVWVnK0RTcmR3RUg0OXVpalFpaEN6emUyd1lmYktNPQ==',
        'Content-Type': 'application/json',
        'Cookie': 'TS0106293e=0132a679c0de492f78ad9167fec695dcf72b9d0de7a543fa85e5489408147766e8adef82615bb0185e4589ae99f41271aad5ae2091'
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    print(response.text)
doc = frappe.get_doc("Sales Invoice", "ACC-SINV-2023-00007")

value_retunred  =compliance_Invoice_API_Call(doc)

# print("starting here ")

# compliance_Invoice_API_Call(invoice,uuid1) 





































# def create_Signcerti_Root():
#     with open('root.cnf', 'rb') as config_file:
#         config_data= config_file.read()
#     root_pri = crypto.PKey()
#     root_pri.generate_key(crypto.TYPE_RSA, 2048)
#     root_certi = crypto.X509()
#     print(config_data) 
#     return root_pri, root_certi
     
# def create_Csr():
#     csr_pri = crypto.PKey()
#     csr_pri.generate_key(crypto.TYPE_RSA, 2048)
#     csr = crypto.X509Req()
#     csr.get_subject().CN = "IntermediateCA"
#     csr.set_pubkey(csr_pri)
#     csr.sign(csr_pri, "sha256")
#     csr_pem = crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr)  
#     with open("my.csr", "wb") as csr_file:
#         csr_file.write(csr_pem)
#     return csr  

# def sign_Intermediate_Cert(root_pri, root_certi):
#     with open("my.csr", "rb") as csr_file:
#         csr_data = csr_file.read()
#     csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr_data)
#     return crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr).decode()
# root_pri, root_certi = create_Signcerti_Root()
# csr = create_Csr()
# csr_output = sign_Intermediate_Cert(root_pri, root_certi)
# print(csr_output)

# def create_Signcerti_Root():
#     with open('root.cnf', 'rb') as config_file:
#         config = config_file.read()
#     root_pri = crypto.PKey()
#     root_pri.generate_key(crypto.TYPE_RSA, 2048)
#     root_certi = crypto.X509()
#     print(config) 
#     return root_pri, root_certi
     
# def create_Csr():
#     csr_pri = crypto.PKey()
#     csr_pri.generate_key(crypto.TYPE_RSA, 2048)
#     csr = crypto.X509Req()
#     csr.get_subject().CN = "IntermediateCA"
#     csr.set_pubkey(csr_pri)
#     csr.sign(csr_pri, "sha256")
#     with open("my.csr", "wb") as csr_file:
#         csr_file.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr))
# def sign_Intermediate_Cert(root_private_key, root_certificate):
#     with open("my.csr", "rb") as csr_file:
#         csr_data = csr_file.read()
    
#     csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr_data)
#     my_certi = crypto.X509()
#     my_certi.set_version(2)
#     my_certi.set_serial_number(2)
#     my_certi.set_issuer(root_certificate.get_subject()) 
#     my_certi.set_pubkey(csr.get_pubkey()) 
#     my_certi.sign(root_private_key, "sha256")
#     print(crypto.dump_certificate(crypto.FILETYPE_TEXT, my_certi).decode())
#     print(csr_data)
# root_pri, root_certi= create_Signcerti_Root()
# create_Csr()
# sign_Intermediate_Cert(root_pri, root_certi)









 










# def create_Certi():
#     key = crypto.PKey()
#     key.generate_key(crypto.TYPE_RSA, 2048)
#     cert = crypto.X509()
#     cert.gmtime_adj_notBefore(0)
#     cert.gmtime_adj_notAfter(365 * 24 * 60 * 60) 
#     cert.set_issuer(cert.get_subject())
#     cert.set_pubkey(key)
#     cert.sign(key, 'sha256')
#     private_key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
#     certificate_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
#     with open('test.key', 'wb') as key_file, open('test.cer', 'wb') as cer_file:
#         key_file.write(private_key_pem)
#         cer_file.write(certificate_pem)
#     print(crypto.dump_certificate(crypto.FILETYPE_TEXT, cert).decode())
# create_Certi()  

        












# sellerName = "Firoz Ashraf"
# vatNumber = "1234567891"
# timeStamp = "2021-11-17 08:30:00"
# invoiceTotal = "100.00"
# vatTotal = "15.00"

# # TLV encode into a Chilkat BinData object.
# bdTlv = chilkat2.BinData()

# charset = "utf-8"

# tag = 1
# bdTlv.AppendByte(tag)
# bdTlv.AppendCountedString(1,False,sellerName,charset)
# tag = tag + 1
# # This is tag 2
# bdTlv.AppendByte(tag)
# bdTlv.AppendCountedString(1,False,vatNumber,charset)
# tag = tag + 1
# # This is tag 3
# bdTlv.AppendByte(tag)
# bdTlv.AppendCountedString(1,False,timeStamp,charset)
# tag = tag + 1
# # This is tag 4
# bdTlv.AppendByte(tag)
# bdTlv.AppendCountedString(1,False,invoiceTotal,charset)
# tag = tag + 1
# # This is tag 5
# bdTlv.AppendByte(tag)
# bdTlv.AppendCountedString(1,False,vatTotal,charset)






















# success = True
# sbXml = chilkat2.StringBuilder()
# success = sbXml.LoadFile("rendered_text","utf-8")

# if (success == False):
#     print("Failed to load XML file to be signed.")
#     sys.exit()

