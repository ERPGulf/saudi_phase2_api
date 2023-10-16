import frappe
frappe.init(site="husna.erpgulf.com")
frappe.connect()
from frappe.model.document import Document
class ChildDoc(Document):
# frappe.db.get_value(doctype,name,fieldname)
    def validate(self):
        self.get_value()

    def get_value(self):
        first_name,last_name = frappe.db.get_value('Parent Doc+','anu',['first_name','last_name'])
        frappe.msgprint(("the fisrt name is {0} and last name is {1}").format(first_name,last_name))