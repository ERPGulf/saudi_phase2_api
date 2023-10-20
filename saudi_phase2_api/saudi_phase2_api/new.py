
import frappe
frappe.init(site="husna.erpgulf.com")
frappe.connect()
import requests    
import pyqrcode
import os
# from path import Path
from frappe.utils import cstr, flt
import uuid
from pickle import FALSE
import time
from frappe.utils.data import add_to_date, get_time, getdate
from base64 import b64encode
import base64
import json
import hashlib
from fatoora import Fatoora
from frappe.utils.file_manager import remove_file
from OpenSSL import crypto
from subprocess import call
import pprint

