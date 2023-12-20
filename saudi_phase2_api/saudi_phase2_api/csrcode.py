
import frappe
# frappe.init(site="husna.erpgulf.com")
# frappe.connect()
import subprocess
import base64
import json
import sys
import requests
def _execute_in_shell(cmd, verbose=False, low_priority=False, check_exit_code=False):
                # using Popen instead of os.system - as recommended by python docs
                import shlex
                import tempfile
                from subprocess import Popen
                
                env_variables = {"MY_VARIABLE": "some_value", "ANOTHER_VARIABLE": "another_value"}
                if isinstance(cmd, list):
                    # ensure it's properly escaped; only a single string argument executes via shell
                    cmd = shlex.join(cmd)

                    # process = subprocess.Popen(command_sign_invoice, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env_variables)

                
                with (tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr):
                    kwargs = {"shell": True, "stdout": stdout, "stderr": stderr}

                    if low_priority:
                        kwargs["preexec_fn"] = lambda: os.nice(10)

                    p = Popen(cmd, **kwargs)
                    exit_code = p.wait()

                    stdout.seek(0)
                    out = stdout.read()

                    stderr.seek(0)
                    err = stderr.read()
                failed = check_exit_code and exit_code

                if verbose or failed:
                    if err:
                        print(err)
                    if out:
                        print(out)
                if failed:
                    raise Exception("Command failed")
                return err, out

@frappe.whitelist(allow_guest=True)
def generate_csr():
                settings=frappe.get_doc('Zatca setting')
                csr_config_file = 'sdkcsrconfig.properties'
                private_key_file = 'sdkprivatekey.pem'
                generated_csr_file = 'sdkcsr.pem'
                SDK_ROOT='/opt/sdk/sdk-2.7'
                path_string=f"export SDK_ROOT={SDK_ROOT} && export FATOORA_HOME=$SDK_ROOT/Apps && export SDK_CONFIG=$SDK_ROOT/Configuration/config.json && export PATH=$PATH:$FATOORA_HOME &&  "
                command_generate_csr =  path_string  + f'fatoora -csr -csrConfig {csr_config_file} -privateKey {private_key_file} -generatedCsr {generated_csr_file} -pem'
                try:
                    err,out = _execute_in_shell(command_generate_csr)
                    frappe.msgprint(out)
                    with open("generated-csr-20231218053250.csr", "r") as file_csr:
                        get_csr = file_csr.read()
                    file = frappe.get_doc(
                        {
                            "doctype": "File",
                            "file_name": f"generated-csr-{settings.name}.csr",
                            "attached_to_doctype": settings.doctype,
                            "attached_to_name": settings.name,
                            "content": get_csr,
                        }
                    )
                    file.save()
                    frappe.msgprint("CSR generation successful. CSR saved")
                except Exception as e:
                    frappe.msgprint(err)
                    frappe.msgprint("An error occurred: " + str(e))


@frappe.whitelist(allow_guest=True)
def create_CSID(): 
        try:
            settings=frappe.get_doc('Zatca setting')     
            with open("generated-csr-20231218053250.csr", "r") as f:
                csr_contents = f.read()
            # frappe.msgprint(csr_contents)
            url = "https://gw-fatoora.zatca.gov.sa/e-invoicing/developer-portal/compliance"
            payload = json.dumps({
            "csr": csr_contents
            })
            headers = {
            'accept': 'application/json',
            'OTP': '123345',
            'Accept-Version': 'V2',
            'Content-Type': 'application/json',
            'Cookie': 'TS0106293e=0132a679c07382ce7821148af16b99da546c13ce1dcddbef0e19802eb470e539a4d39d5ef63d5c8280b48c529f321e8b0173890e4f'
            }
            response = requests.request("POST", url, headers=headers, data=payload)
            print(response.text)
            frappe.msgprint(response.text)
            frappe.msgprint("the CSID formed through url")
        except Exception as e:
                    frappe.msgprint("error")

