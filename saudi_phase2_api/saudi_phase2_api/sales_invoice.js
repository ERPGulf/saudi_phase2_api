frappe.ui.form.on("myzatca_test", {
    refresh: function(frm) {
       
      frm.add_custom_button(__("Click"), function() {
        
        frm.call("button_click", {
            token: frm.doc.custom_token,
            recipient :frm.doc.custom_to_number,
            message:frm.doc.custom_message
                }).then(r => {
                console.log(r.message)
                frappe.msgprint(r.message);     
            })
            }, __("send"));
    }
});