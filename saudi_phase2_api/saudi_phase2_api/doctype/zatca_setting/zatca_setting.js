// Copyright (c) 2023, ERPGulf and contributors
// For license information, please see license.txt

frappe.ui.form.on("Zatca setting", {
	refresh(frm) {
       
    },
    csid_attach: function (frm) {
            frappe.call({
                method: "saudi_phase2_api.saudi_phase2_api.csrcode.create_CSID",
                args: {
                  
                },
                callback: function (r) {
                    if (!r.exc) {
                        frm.save();
                        window.open(r.message.url);
                    }
                },
            });
        },
    create_csr: function (frm) {
        frappe.call({
            method: "saudi_phase2_api.saudi_phase2_api.csrcode.generate_csr",
            args: {
              
            },
            callback: function (r) {
                if (!r.exc) {
                    frm.save();
                    window.open(r.message.url);
                }
            },
        });
    }
    
});
