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
    return total_in_dollars

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
    print(f"Exchange rate from SAR to USD: {exchange_rate}")
else:
    print("Failed to fetch exchange rate.")

# # import frappe
# # frappe.init("husna.erpgulf.com")
# # frappe.connect()

# # exchange_rate = frappe.get_list('Currency rate', fields={'currency','value'},filters={'currency':'USD'})
# # #print(exchange_rate)
# # print(exchange_rate[0].value)

# # # if exchange_rate:
# # #         print (exchange_rate[0]['value'])
# # # else:
# # #        print("")
# # # list
# # # array
# # #dict
# #CODE FOR ENCODE AND DECODE A SAMPLE TEXT
# import base64
# string = "Hello World"
# encoded_string = base64.b64encode(string.encode()).decode()
# decoded_string = base64.b64decode(encoded_string).decode()
# print("Encoded string is:", encoded_string)
# print("Decoded string is", decoded_string)





#   CODE FOR SENDING A MESSAGE TO PHONE AS SMS

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







# CODE FOR FINDING THE SUM OF TOTAL QUANTITY  OF THE DOCTYPE SALE INVOICE OF FRAPPE ADMINISTARTION

# @frappe.whitelist(allow_guest=True)
# def pingpong3():
#     data = frappe.get_value('Sales Invoice',)
#     data1 = data.as_dict()
#     total_qty = 0
#     for item in data1[“items”]:
#         total_qty += item[“qty”]
#     return total_qty




#CODE FOR TEST 4 USED TO ADD THE CURRENCY VALUE FROM INTERNET BY CONVERTION OF THE TOTAL QUANTITY

#import frappe
# import os
# import requests

# @frappe.whitelist(allow_guest=True)
# def pingpong3():
#     data = frappe.get_doc('Sales Invoice', 'ACC-SINV-2023-00003')
#     data1 = data.as_dict()
#     total_qty = 0
#     for item in data1["items"]:
#         total_qty += item["qty"]
#     exchange_rate = get_currency_exchange_rate("SAR", "USD")  
#     total_in_dollars = total_qty * exchange_rate
#     return total_in_dollars

# def get_currency_exchange_rate(from_currency, to_currency):
#     try:
#         url = f"https://api.exchangerate.host/convert?from={from_currency}&to={to_currency}&amount=1"
#         response = requests.get(url)
#         if response.status_code == 200:
#             data = response.json()
#             exchange_rate = data.get("result")

#             return exchange_rate
#         else:
#             print(f"API request failed with status code {response.status_code}")
#             return None
#     except Exception as e:
#         print(f"An error occurred: {str(e)}")
#         return None
# exchange_rate = get_currency_exchange_rate("SAR", "USD")

# if exchange_rate is not None:
#     print(f"Exchange rate from SAR to USD: {exchange_rate}")
# else:
#     print("Fail")



# TEST 5 as heading for adding the single variable using frappe.valuethat format

# import frappe
# import os
# import requests

# @frappe.whitelist(allow_guest=True)
# def pingpong3():
#     data = frappe.get_doc('Sales Invoice', 'ACC-SINV-2023-00003')
#     data1 = data.as_dict()
#     total_qty = 0
#     for item in data1["items"]:
#         total_qty += item["qty"]
#     exchange_rate = get_currency_exchange_rate("SAR", "USD")  
#     total_in_dollars = total_qty * exchange_rate
#     new_value = frappe.db.get_value('Company', data.company, 'default_currency')
#     return total_in_dollars, new_value
# def get_currency_exchange_rate(from_currency, to_currency):
#     try:
#         url = f"https://api.exchangerate.host/convert?from={from_currency}&to={to_currency}&amount=1"
#         response = requests.get(url)
#         if response.status_code == 200:
#             data = response.json()
#             exchange_rate = data.get("result")

#             return exchange_rate
#         else:
#             print(f"API request failed with status code {response.status_code}")
#             return None
#     except Exception as e:
#         print(f"An error occurred: {str(e)}")
#         return None

# exchange_rate = get_currency_exchange_rate("SAR", "USD")

# if exchange_rate is not None:
#     print(f"Exchange  SAR to USD: {exchange_rate}")
# else:
#     print("Fail")

# CURRENCY COVERTION USING DOCTYPE CURRENCY RATE
# @frappe.whitelist(allow_guest=True)
# def pingpong2(fromcurrency,tocurrency,amount):
#     data = frappe.db.get_list('Currency rate',
#     ['currency', 'value'])
#     currency_dict={currency['currency']:currency['value'] for currency in data}
#     source_rate = currency_dict[fromcurrency]
#     destination_rate = currency_dict[tocurrency]
#     amount = float(amount)
#     new_amount = amount* (destination_rate / source_rate)
#     return new_amount



# CODE FOR USING dict
# #     # currencies={"AED": 3.917049,
# #     #             "AFN": 84.425143,
# #     #             "ALL": 106.861114,
# #     #             "AMD": 409.381681,
# #     #             "ANG": 1.919039,
# #     #             "AOA": 882.304758,
# #     #             "ARS": 372.678734}
# #     # source_rate = currencies[fromcurrency]
# #     # destination_rate =currencies[tocurrency]
# #     # amount = float(amount)
# #     # new_amount = amount * (destination_rate / source_rate)
# #     # return new_amount



#  LISTINN ONE SPECIFIC VALUE
 
# def get_currency_exchange_rate(value):
#     exchange_rate = frappe.get_list('Currency rate',fields={'currency','value'},filters={'currency':'SAR'})
#     return  exchange_rate[0].value
