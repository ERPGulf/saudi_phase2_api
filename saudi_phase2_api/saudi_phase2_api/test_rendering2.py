import frappe
import os
frappe.init(site="husna.erpgulf.com")
frappe.connect()
context = {
 "name":"husna","from_name":"manakkot","success":True
}
template_name = "saudi_phase2_api/saudi_phase2_api/e_test.xml"
rendered_text = frappe.render_template(template_name, context)
print(rendered_text)

# cwd = os.getcwd()


# with open("output.xml", "r") as file1:
#     output_file = file1.read()
# print(output_file)