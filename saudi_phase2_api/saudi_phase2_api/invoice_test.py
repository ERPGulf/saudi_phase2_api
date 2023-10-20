
import frappe
frappe.init(site="husna.erpgulf.com")
frappe.connect()
from subprocess import call
import subprocess
import requests
import json
def extract_Invoice_Actuavalues():
    invoice = frappe.get_doc("Sales Invoice", "ACC-SINV-2023-00007")
    company = frappe.get_doc("Company", invoice.company)
    invoice.company_data = company
    # company_address = frappe.get_doc("Address", invoice.company_address)
    company_address = "Barwa Tower C-Ring Road Doha"
    invoice.company_address_data = company_address
    invoice.customer_data = frappe.get_doc("Customer", invoice.customer)
    # customer_address = frappe.get_doc("Address", invoice.customer_address)
    customer_address= "XXX PO"
    invoice.customer_address_data = customer_address
    
extract_Invoice_Actuavalues()
