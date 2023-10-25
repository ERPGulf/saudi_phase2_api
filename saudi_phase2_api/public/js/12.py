import frappe
frappe.init(site="husna.erpgulf.com")
frappe.connect()
@frappe.whitelist()
def button():
    return "hello"