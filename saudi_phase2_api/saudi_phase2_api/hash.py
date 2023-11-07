import frappe
frappe.init(site="husna.erpgulf.com")
frappe.connect()
import hashlib
import base64

def calculate_next_invoice_hash(last_hash):
    last_hash_bytes = base64.b64decode(last_hash.encode('utf-8'))
    next_hash_bytes = bytearray(last_hash_bytes)
    next_hash_bytes[-1] += 1 
    next_hash = base64.b64encode(next_hash_bytes).decode('utf-8')
    print(next_hash)
    return next_hash


def calculate_invoice_hash(xml_content):
    standard_invoice = xml_content 
    hash_obj = hashlib.sha256()
    hash_obj.update(standard_invoice.encode('utf-8'))
    binary_hash = hash_obj.digest()
    print(binary_hash)
    base64_hash = base64.b64encode(binary_hash).decode('utf-8')
    print(base64_hash)
    return base64_hash

xml_content = "saudi_phase2_api/saudi_phase2_api/e_test.xml"

initial_hash = calculate_invoice_hash(xml_content)
# xml_content = xml_content.replace('<InitialHash></InitialHash>', f'<InitialHash>{initial_hash}</InitialHash>')
last_used_hash = initial_hash 
print(last_used_hash)
frappe.get_doc("Saudi Zatca settings").pih = last_used_hash



