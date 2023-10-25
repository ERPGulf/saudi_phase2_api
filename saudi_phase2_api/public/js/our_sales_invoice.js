frappe.ui.form.on("Sales Invoice", {
    refresh: function(frm) {
        frm.add_custom_button(__("click"), function() {
            frm.call({
                method:  "saudi_phase2_api.saudi_phase2_api.myzatca_test.invoice_Zatca_call",
                args: {
                    invoice_number : "ACC-SINV-2023-00012",
                },
                callback: function(response) {
                    if (response.message) {  
                        frappe.msgprint(response.message);
                       
                    }
                }
            });
        }, __("sale invoice button"));
    }
});

