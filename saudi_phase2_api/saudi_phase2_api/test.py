# import frappe
# import os
# from twilio.rest import Client
# account_sid = 'ACbfd204d4101882f6a20c4e06136d2bb3'
# auth_token = '358440022aff2ce4006f15ceeba2bf25'
# client = Client(account_sid, auth_token)
# message = client.messages.create(
#   from_='+18789999387',
#   body='hello testing ..',
#   to='+917306204060'
# )
# print(message.sid)

# @frappe.whitelist(allow_guest=True)
# def pingpong2(fromcurrency,tocurrency,amount):
#     data = frappe.db.get_list('Currency rate',
#     ['currency', 'value'])
#     currency_dict={currency['currency']:currency['value'] for currency in data}


#     # currencies={"AED": 3.917049,
#     #             "AFN": 84.425143,
#     #             "ALL": 106.861114,
#     #             "AMD": 409.381681,
#     #             "ANG": 1.919039,
#     #             "AOA": 882.304758,
#     #             "ARS": 372.678734}
#     # source_rate = currencies[fromcurrency]
#     # destination_rate =currencies[tocurrency]
#     # amount = float(amount)
#     # new_amount = amount * (destination_rate / source_rate)
#     # return new_amount

# # data = frappe.db.get_list('Currency rate') 

#     source_rate = currency_dict[fromcurrency]
#     destination_rate = currency_dict[tocurrency]
#     amount = float(amount)
#     new_amount = amount* (destination_rate / source_rate)
#     return new_amount


#    data = frappe.db.get_list ('Sales Invoice',
#     # filters={'name':'ACC-SINV-2023-00003'},
#     fields=['customer_name', 'company','base_paid_amount'], )
# return data


# @frappe.whitelist(allow_guest=True)
# def pingpong3():
#     var1= frappe.get_doc('name','ACC-SINV-2023-00003')
#     var1.as_dict()
#     {
#     'Customer': 'West View Software Ltd.',
#     'company': 'Husna (Demo)',
#     'Items': [
#         {'Item': 'SKU001:T-shirt', 'Quantity': '25'},
#         {'Item': 'SKU002:Laptop', 'Quantity': '15'},
#         ]
#     }
#     result = sum(item['Quantity'] for item in var1['Items'])
#     var1['TotalQuantity'] = result
#     return(var1)

   
# @frappe.whitelist(allow_guest=True)
# def pingpong3():
#        data = frappe.db.get_list ('Sales Invoice',
#                     filters={'name':'ACC-SINV-2023-00003'},
#                     fields=['customer_name', 'company','base_paid_amount'], )

#  var1_dict = frappe.get_doc('Sales Invoice', 'ACC-SINV-2023-00003')  
    
#     var1_dict = var1.as_dict()
#     {
#     'Customer': 'West View Software Ltd.',
#     'company': 'Husna (Demo)',
#     'Items': [
#         {'Item': 'SKU001:T-shirt', 'Quantity': '25'},
#         {'Item': 'SKU002:Laptop', 'Quantity': '15'},
#         ]
#     }
#     for item in var1_dict.get('items', []):
#         item['Quantity'] = int(item.get('Quantity',0))
#     total_quantity = sum(item['Quantity'] for item in var1_dict.get('items', []))
#     var1_dict['TotalQuantity'] = total_quantity

#     return var1_dict




    


   # data.as_dict()
    # {
    # 'Customer': 'West View Software Ltd.',
    # 'company': 'Husna (Demo)',
    # 'Items': [{'Item': 'SKU001:T-shirt', 'Quantity': '25'},
    #     {'Item': 'SKU002:Laptop', 'Quantity': '15'},]
    # }

import frappe
import os
import requests

@frappe.whitelist(allow_guest=True)
def pingpong3():
    data = frappe.get_doc('Sales Invoice', 'ACC-SINV-2023-00003')
    data1 = data.as_dict()
    total_qty = 0
    for item in data1["items"]:
        total_qty += item["qty"]
    exchange_rate = get_currency_exchange_rate("SAR", "USD")  
    total_in_dollars = total_qty * exchange_rate
    new_value = frappe.db.get_value('Company', data.company, 'default_currency')
    return total_in_dollars, new_value
def get_currency_exchange_rate(from_currency, to_currency):
    try:
        url = f"https://api.exchangerate.host/convert?from={from_currency}&to={to_currency}&amount=1"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            exchange_rate = data.get("result")

            return exchange_rate
        else:
            print(f"API request failed with status code {response.status_code}")
            return None
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return None

exchange_rate = get_currency_exchange_rate("SAR", "USD")

if exchange_rate is not None:
    print(f"Exchange  SAR to USD: {exchange_rate}")
else:
    print("Fail")