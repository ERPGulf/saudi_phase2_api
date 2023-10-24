frappe.ui.form.on("Sales Invoice", "refresh", function(frm) {
    frm.add_custom_button(__("Do Something"), function() {
        alert("Hello from client script")
    });
});