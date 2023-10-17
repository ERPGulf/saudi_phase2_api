
import frappe
frappe.init(site="husna.erpgulf.com")
frappe.connect()
import requests
import json

url = "https://gw-fatoora.zatca.gov.sa/e-invoicing/developer-portal/compliance/invoices"

payload = json.dumps({
  "invoiceHash": "PEx8bNFcEMEpHzUVvQntQI6ot8eFqTT/l59b+H1HqX4=",
  "uuid": "3cf5ee18-ee25-44ea-a444-2c37ba7f28be",
  "invoice": "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4NCiA8SW52b2ljZSB4bWxucz0idXJuOm9hc2lzOm5hbWVzOnNwZWNpZmljYXRpb246dWJsOnNjaGVtYTp4c2Q6SW52b2ljZS0yIiB4bWxuczpjYWM9InVybjpvYXNpczpuYW1lczpzcGVjaWZpY2F0aW9uOnVibDpzY2hlbWE6eHNkOkNvbW1vbkFnZ3JlZ2F0ZUNvbXBvbmVudHMtMiIgeG1sbnM6Y2JjPSJ1cm46b2FzaXM6bmFtZXM6c3BlY2lmaWNhdGlvbjp1Ymw6c2NoZW1hOnhzZDpDb21tb25CYXNpY0NvbXBvbmVudHMtMiIgeG1sbnM6ZXh0PSJ1cm46b2FzaXM6bmFtZXM6c3BlY2lmaWNhdGlvbjp1Ymw6c2NoZW1hOnhzZDpDb21tb25FeHRlbnNpb25Db21wb25lbnRzLTIiPjxleHQ6VUJMRXh0ZW5zaW9ucz4NCiAgICAgPGV4dDpVQkxFeHRlbnNpb24+DQogICAgICAgICA8ZXh0OkV4dGVuc2lvblVSST51cm46b2FzaXM6bmFtZXM6c3BlY2lmaWNhdGlvbjp1Ymw6ZHNpZzplbnZlbG9wZWQ6eGFkZXM8L2V4dDpFeHRlbnNpb25VUkk+DQogICAgICAgICA8ZXh0OkV4dGVuc2lvbkNvbnRlbnQ+DQogICAgICAgICAgICAgPHNpZzpVQkxEb2N1bWVudFNpZ25hdHVyZXMgeG1sbnM6c2lnPSJ1cm46b2FzaXM6bmFtZXM6c3BlY2lmaWNhdGlvbjp1Ymw6c2NoZW1hOnhzZDpDb21tb25TaWduYXR1cmVDb21wb25lbnRzLTIiIHhtbG5zOnNhYz0idXJuOm9hc2lzOm5hbWVzOnNwZWNpZmljYXRpb246dWJsOnNjaGVtYTp4c2Q6U2lnbmF0dXJlQWdncmVnYXRlQ29tcG9uZW50cy0yIiB4bWxuczpzYmM9InVybjpvYXNpczpuYW1lczpzcGVjaWZpY2F0aW9uOnVibDpzY2hlbWE6eHNkOlNpZ25hdHVyZUJhc2ljQ29tcG9uZW50cy0yIj4NCiAgICAgICAgICAgICAgICAgPHNhYzpTaWduYXR1cmVJbmZvcm1hdGlvbj4NCiAgICAgICAgICAgICAgICAgICAgIDxjYmM6SUQ+dXJuOm9hc2lzOm5hbWVzOnNwZWNpZmljYXRpb246dWJsOnNpZ25hdHVyZToxPC9jYmM6SUQ+DQogICAgICAgICAgICAgICAgICAgICA8c2JjOlJlZmVyZW5jZWRTaWduYXR1cmVJRD51cm46b2FzaXM6bmFtZXM6c3BlY2lmaWNhdGlvbjp1Ymw6c2lnbmF0dXJlOkludm9pY2U8L3NiYzpSZWZlcmVuY2VkU2lnbmF0dXJlSUQ+DQogICAgICAgICAgICAgICAgICAgICANCiAgICAgICAgICAgICAgICAgPGRzOlNpZ25hdHVyZSB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyIgSWQ9InNpZ25hdHVyZSI+DQogIDxkczpTaWduZWRJbmZvPg0KICAgIDxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwNi8xMi94bWwtYzE0bjExIi8+DQogICAgPGRzOlNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZHNpZy1tb3JlI3JzYS1zaGEyNTYiLz4NCiAgICA8ZHM6UmVmZXJlbmNlIElkPSJpbnZvaWNlU2lnbmVkRGF0YSIgVVJJPSIiPjxkczpUcmFuc2Zvcm1zPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy9UUi8xOTk5L1JFQy14cGF0aC0xOTk5MTExNiI+PGRzOlhQYXRoPm5vdCgvL2FuY2VzdG9yLW9yLXNlbGY6OmV4dDpVQkxFeHRlbnNpb25zKTwvZHM6WFBhdGg+PC9kczpUcmFuc2Zvcm0+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnL1RSLzE5OTkvUkVDLXhwYXRoLTE5OTkxMTE2Ij48ZHM6WFBhdGg+bm90KC8vYW5jZXN0b3Itb3Itc2VsZjo6Y2FjOlNpZ25hdHVyZSk8L2RzOlhQYXRoPjwvZHM6VHJhbnNmb3JtPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy9UUi8xOTk5L1JFQy14cGF0aC0xOTk5MTExNiI+DQogICAgPGRzOlhQYXRoPm5vdCgvL2FuY2VzdG9yLW9yLXNlbGY6OmNhYzpBZGRpdGlvbmFsRG9jdW1lbnRSZWZlcmVuY2VbY2JjOklEPSdRUiddKTwvZHM6WFBhdGg+PC9kczpUcmFuc2Zvcm0+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDYvMTIveG1sLWMxNG4xMSIvPjwvZHM6VHJhbnNmb3Jtcz4NCiAgICAgIDxkczpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNzaGEyNTYiLz4NCiAgICAgIDxkczpEaWdlc3RWYWx1ZT5zTE4zV0pITzFpc3JSOW8xYVFhOVNhNUl6LzBsakhJRDQ1UU9RdUYrUUJ3PTwvZHM6RGlnZXN0VmFsdWU+DQogICAgPC9kczpSZWZlcmVuY2U+DQogICAgPGRzOlJlZmVyZW5jZSBUeXBlPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjU2lnbmF0dXJlUHJvcGVydGllcyIgVVJJPSIjeGFkZXNTaWduZWRQcm9wZXJ0aWVzIj4NCiAgICAgIDxkczpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNzaGEyNTYiLz4NCiAgICAgIDxkczpEaWdlc3RWYWx1ZT5aR0poTXpjM1pXSTJORE0xTUdOaU1XVXlORGxrWmpZeFkyWmtPR0l4T0RneFlqTmpORFU0TldVMlpXRXlaVEE0TnpRMFpEUXpZamMwWldObU1UaGtOdz09PC9kczpEaWdlc3RWYWx1ZT4NCiAgICA8L2RzOlJlZmVyZW5jZT4NCiAgPC9kczpTaWduZWRJbmZvPg0KICA8ZHM6U2lnbmF0dXJlVmFsdWU+ZkJFVkpPcVBGNWUxVU5BNDMzMk44THBBQS9sdVlPQUs3UW0xZDdOYzR4Y1kyK2dySGxLMGpOVlZGKzV1VTh3d3l2dEhhbm9yMFF4NXA1MldUK1Z0eS9VRWpHakMwY1JLNDg0TzBBcWVCczhYTUdZM3VHa1JBNFdUaGF2ZTV2TStNSVJySjYyNzFDLzBDMFpKczdPU0d3QW93WW5TZjZIc1NmTUhHTGw4L0RRRzUvVzI1N2VlcjF0RUtoMUhzbmtoOFJmaHBMUXRsTHRpNXRwaFF4QmtIMjlEbTV1ZWo5RDVndkM0VnR3UTdDVEhCK3BzNi9DUlQ1dXdzWXJFS0lXb0tKaTZFNUtFNmJHSlkzT1JtNjFCaVFFRFV0alBlMXQzN0JSQU9RUFRvYmlyWGV3SE5EU1ZUN0dsdHBXZWRFR2JjSXVlOE9aU3lxeEFUTjhsMkgrMk1RPT08L2RzOlNpZ25hdHVyZVZhbHVlPg0KICA8ZHM6S2V5SW5mbz4NCiAgICA8ZHM6WDUwOURhdGE+DQogICAgICA8ZHM6WDUwOUNlcnRpZmljYXRlPk1JSURkVENDQWwwQ0ZET3BRQVhQVWpUZUJKczFBOFBCOXUrcC9xT2JNQTBHQ1NxR1NJYjNEUUVCQ3dVQU1IY3hDekFKQmdOVkJBWVRBbE5CTVE0d0RBWURWUVFJREFWU1NWbEJSREVMTUFrR0ExVUVCd3dDUlZJeEN6QUpCZ05WQkFvTUFsZEZNUkF3RGdZRFZRUUxEQWRGVWxCSFZVeEdNUXd3Q2dZRFZRUUREQU5GVWxBeEhqQWNCZ2txaGtpRzl3MEJDUUVXRDJoMWMyNWhRR2R0WVdsc0xtTnZiVEFlRncweU16RXdNVFl3TmpVeE16aGFGdzB5TXpFeE1UVXdOalV4TXpoYU1IY3hDekFKQmdOVkJBWVRBbE5CTVE0d0RBWURWUVFJREFWU1NWbEJSREVMTUFrR0ExVUVCd3dDUlZJeEN6QUpCZ05WQkFvTUFsZEZNUkF3RGdZRFZRUUxEQWRGVWxCSFZVeEdNUXd3Q2dZRFZRUUREQU5GVWxBeEhqQWNCZ2txaGtpRzl3MEJDUUVXRDJoMWMyNWhRR2R0WVdsc0xtTnZiVENDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFMMUNPSk4ydS8xNkFRbTV2SWJwZDYvS0xUdURhL1FlSC9DOCs5U2ROd2Rka1ZFMUdpNkExVlhHeWlBV1RTeFhJQlV1QWw0UnBzQmR3WHcxeE1NK0R2eTF5UFMxMzNFaHF4RGFkRllSNWtHcUd6Y1p6U29pL3VRaGN2ODZOUk1waCt2YmRuVXhjYVdQZG5JR21yVUN5YUdnSmxzcXlSc3ltdElxOGJ0VjF4SDBKWkpLT3VUVGM1aTRPc2J5SVNUUXhSTzVkWFhUN3U3SDBCWXRsNmZ3azNGTXVzZExFQlZja09qQVhTVlZibU5TczBZWU54QVRmMnZ3eHcyRkN4VW9RL0RIdmxWL2VmM2Y5ay9KeHNsaEU0eGlCS1NIZXM1Tk1XMFRXc2VWNlY3QVE4WCs2cFNISVdvREFsa2JOaC9EN2Vzd21ZK1dPL1lrZFN5M0k5czNsVzBDQXdFQUFUQU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFQZkNOSXgzWWI2SlQyZ2I3NFBnMFRaNXZjVDd1NGdqY0Z4VEtzU3Y3OG1Rei9GWERTOGZNRG5jR0pRMVRRWUozSllLY0ZGTjFxS2lDc2hlT0ZPMzFqZFRFVEpmWHhrR3V3RHJTc1paQ2ZMMW5RenpNMk5OeWRhNjMxcVFOQldFb1M4eXFBSmdnQkV6cDcrbDVONnFyNW9lTGRWUUZrTEZxQVJ2SzFvWjZ4ZzNPZ2daZHp0K2dpeVR1cWlhVjd6NkZEa1B5YzlFSGtaZW1EQXprQ0l0SjZaeW56cFZPYkowaDdJYzloL2JzVXg3MEdSclBYZGNYNG95NEtrS3EvN2NHVUNyN05CL1BrK01kYXVWZDFaNzNhNmlNLzBVK21FS2RBdU9tMmdtNjczbUdyS2N2MlA5eDBhTGxOeUh4eEFOVDNQdzJ0NStmNEV5WEhQejBvMTNUbEE9PTwvZHM6WDUwOUNlcnRpZmljYXRlPg0KICAgIDwvZHM6WDUwOURhdGE+DQogIDwvZHM6S2V5SW5mbz4NCiAgPGRzOk9iamVjdD4NCiAgICA8eGFkZXM6UXVhbGlmeWluZ1Byb3BlcnRpZXMgeG1sbnM6eGFkZXM9Imh0dHA6Ly91cmkuZXRzaS5vcmcvMDE5MDMvdjEuMy4yIyIgVGFyZ2V0PSJzaWduYXR1cmUiPg0KICAgIDx4YWRlczpTaWduZWRQcm9wZXJ0aWVzIElkPSJ4YWRlc1NpZ25lZFByb3BlcnRpZXMiPg0KICAgICAgICA8eGFkZXM6U2lnbmVkU2lnbmF0dXJlUHJvcGVydGllcz4NCiAgICAgICAgICAgIDx4YWRlczpTaWduaW5nVGltZT4yMDIzLTEwLTE3VDA0OjQ0OjU1WjwveGFkZXM6U2lnbmluZ1RpbWU+DQogICAgICAgICAgICA8eGFkZXM6U2lnbmluZ0NlcnRpZmljYXRlPg0KICAgICAgICAgICAgICAgIDx4YWRlczpDZXJ0Pg0KICAgICAgICAgICAgICAgICAgICA8eGFkZXM6Q2VydERpZ2VzdD4NCiAgICAgICAgICAgICAgICAgICAgICAgIDxkczpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNzaGEyNTYiLz4NCiAgICAgICAgICAgICAgICAgICAgICAgIDxkczpEaWdlc3RWYWx1ZT5PR1ZqTlRCbFpUaGpaV001TUdVd09ESTVObVV6WW1JeVpETmtaV0ZqT1ROak9ETTFZV0V5TmprMlpqZzNNVGMyTjJGaU56VXdNV1UwWkRCaU1HTTFNdz09PC9kczpEaWdlc3RWYWx1ZT4NCiAgICAgICAgICAgICAgICAgICAgPC94YWRlczpDZXJ0RGlnZXN0Pg0KICAgICAgICAgICAgICAgICAgICA8eGFkZXM6SXNzdWVyU2VyaWFsPg0KICAgICAgICAgICAgICAgICAgICAgICAgPGRzOlg1MDlJc3N1ZXJOYW1lPkU9aHVzbmFAZ21haWwuY29tLCBDTj1FUlAsIE9VPUVSUEdVTEYsIE89V0UsIEw9RVIsIFNUPVJJWUFELCBDPVNBPC9kczpYNTA5SXNzdWVyTmFtZT4NCiAgICAgICAgICAgICAgICAgICAgICAgIDxkczpYNTA5U2VyaWFsTnVtYmVyPjI5NDkzMjkzMjQxMzg1NTk5NDA1MjU0MjA1ODkwODU4MzYzMjQ5MzA3NDA5NzA1MTwvZHM6WDUwOVNlcmlhbE51bWJlcj4NCiAgICAgICAgICAgICAgICAgICAgPC94YWRlczpJc3N1ZXJTZXJpYWw+DQogICAgICAgICAgICAgICAgPC94YWRlczpDZXJ0Pg0KICAgICAgICAgICAgPC94YWRlczpTaWduaW5nQ2VydGlmaWNhdGU+DQogICAgICAgIDwveGFkZXM6U2lnbmVkU2lnbmF0dXJlUHJvcGVydGllcz4NCiAgICA8L3hhZGVzOlNpZ25lZFByb3BlcnRpZXM+DQo8L3hhZGVzOlF1YWxpZnlpbmdQcm9wZXJ0aWVzPg0KPC9kczpPYmplY3Q+DQo8L2RzOlNpZ25hdHVyZT48L3NhYzpTaWduYXR1cmVJbmZvcm1hdGlvbj4NCiAgICAgICAgICAgICA8L3NpZzpVQkxEb2N1bWVudFNpZ25hdHVyZXM+DQogICAgICAgICA8L2V4dDpFeHRlbnNpb25Db250ZW50Pg0KICAgICA8L2V4dDpVQkxFeHRlbnNpb24+DQogPC9leHQ6VUJMRXh0ZW5zaW9ucz4NCiAgICANCiAgICA8Y2JjOlByb2ZpbGVJRD5yZXBvcnRpbmc6MS4wPC9jYmM6UHJvZmlsZUlEPg0KICAgIDxjYmM6SUQ+MTAwPC9jYmM6SUQ+DQogICAgPGNiYzpVVUlEPjNjZjVlZTE4LWVlMjUtNDRlYS1hNDQ0LTJjMzdiYTdmMjhiZTwvY2JjOlVVSUQ+DQogICAgPGNiYzpJc3N1ZURhdGU+MjAyMS0wNC0yNTwvY2JjOklzc3VlRGF0ZT4NCiAgICA8Y2JjOklzc3VlVGltZT4xNTozMDowMDwvY2JjOklzc3VlVGltZT4NCiAgICA8Y2JjOkludm9pY2VUeXBlQ29kZSBuYW1lPSIwMTAwMDAwIj4zODg8L2NiYzpJbnZvaWNlVHlwZUNvZGU+DQogICAgPGNiYzpEb2N1bWVudEN1cnJlbmN5Q29kZT5TQVI8L2NiYzpEb2N1bWVudEN1cnJlbmN5Q29kZT4NCiAgICA8Y2JjOlRheEN1cnJlbmN5Q29kZT5TQVI8L2NiYzpUYXhDdXJyZW5jeUNvZGU+DQogICAgPGNiYzpMaW5lQ291bnROdW1lcmljPjI8L2NiYzpMaW5lQ291bnROdW1lcmljPg0KICAgIDxjYWM6QWRkaXRpb25hbERvY3VtZW50UmVmZXJlbmNlPg0KICAgICAgIDxjYmM6SUQ+SUNWPC9jYmM6SUQ+DQogICAgICAgPGNiYzpVVUlEPjQ2NTMxPC9jYmM6VVVJRD4NCiAgICA8L2NhYzpBZGRpdGlvbmFsRG9jdW1lbnRSZWZlcmVuY2U+DQogICAgPGNhYzpBZGRpdGlvbmFsRG9jdW1lbnRSZWZlcmVuY2U+DQogICAgICAgPGNiYzpJRD5QSUg8L2NiYzpJRD4NCiAgICAgICA8Y2FjOkF0dGFjaG1lbnQ+DQogICAgICAgICAgPGNiYzpFbWJlZGRlZERvY3VtZW50QmluYXJ5T2JqZWN0IG1pbWVDb2RlPSJ0ZXh0L3BsYWluIj41ZmVjZWI2NmZmYzg2ZjM4ZDk1Mjc4NmM2ZDY5NmM3OWMyZGJjMjM5ZGQ0ZTkxYjQ2NzI5ZDczYTI3ZmI1N2U5PC9jYmM6RW1iZWRkZWREb2N1bWVudEJpbmFyeU9iamVjdD4NCiAgICAgICA8L2NhYzpBdHRhY2htZW50Pg0KICAgIDwvY2FjOkFkZGl0aW9uYWxEb2N1bWVudFJlZmVyZW5jZT4NCiAgIA0KIDxjYWM6QWRkaXRpb25hbERvY3VtZW50UmVmZXJlbmNlPg0KIDxjYmM6SUQ+UVI8L2NiYzpJRD4NCiA8Y2FjOkF0dGFjaG1lbnQ+DQogICAgPGNiYzpFbWJlZGRlZERvY3VtZW50QmluYXJ5T2JqZWN0IG1pbWVDb2RlPSJ0ZXh0L3BsYWluIj5BUXhHYVhKdmVpQkJjMmh5WVdZQ0NqRXlNelExTmpjNE9URURFekl3TWpFdE1URXRNVGNnTURnNk16QTZNREFFQmpFd01DNHdNQVVGTVRVdU1EQUdMSE5NVGpOWFNraFBNV2x6Y2xJNWJ6RmhVV0U1VTJFMVNYb3ZNR3hxU0VsRU5EVlJUMUYxUml0UlFuYzlCLzltUWtWV1NrOXhVRVkxWlRGVlRrRTBNek15VGpoTWNFRkJMMngxV1U5QlN6ZFJiVEZrTjA1ak5IaGpXVElyWjNKSWJFc3dhazVXVmtZck5YVlZPSGQzZVhaMFNHRnViM0l3VVhnMWNEVXlWMVFyVm5SNUwxVkZha2RxUXpCalVrczBPRFJQTUVGeFpVSnpPRmhOUjFremRVZHJVa0UwVjFSb1lYWmxOWFpOSzAxSlVuSktOakkzTVVNdk1FTXdXa3B6TjA5VFIzZEJiM2RaYmxObU5raHpVMlpOU0VkTWJEZ3ZSRkZITlM5WE1qVTNaV1Z5TVhSRlMyZ3hTSE51YTJnNFVtWm9jRXhSZEd4TWRHazFkSEJvVVhoQ2EwZ3lPVVJ0TlhWbGFqbEVOV2QyUXpSV2RIZFJOME5VU0VJcmNITTJMME5TVkRWMWQzTlpja1ZMU1ZkdlMwcHBOa1UxUzBVMllrZEtXVE5QVW0wMk1VSnBVVVZFVlhScVVHVXhkRE0zUWxKQlQxRlFWRzlpYVhKWVpYZElUa1JUVmxRM1IyeDBjRmRsWkVWSFltTkpkV1U0VDFwVGVYRjRRVlJPT0d3eVNDc3lUVkU5UFFqL01JSUJDZ0tDQVFFQXZVSTRrM2E3L1hvQkNibThodWwzcjhvdE80TnI5QjRmOEx6NzFKMDNCMTJSVVRVYUxvRFZWY2JLSUJaTkxGY2dGUzRDWGhHbXdGM0JmRFhFd3o0Ty9MWEk5TFhmY1NHckVOcDBWaEhtUWFvYk54bk5LaUwrNUNGeS96bzFFeW1INjl0MmRURnhwWTkyY2dhYXRRTEpvYUFtV3lySkd6S2EwaXJ4dTFYWEVmUWxra282NU5Oem1MZzZ4dkloSk5ERkU3bDFkZFB1N3NmUUZpMlhwL0NUY1V5Nngwc1FGVnlRNk1CZEpWVnVZMUt6UmhnM0VCTi9hL0RIRFlVTEZTaEQ4TWUrVlg5NS9kLzJUOG5HeVdFVGpHSUVwSWQ2emsweGJSTmF4NVhwWHNCRHhmN3FsSWNoYWdNQ1dSczJIOFB0NnpDWmo1WTc5aVIxTExjajJ6ZVZiUUlEQVFBQkNmODk4STBqSGRodm9sUGFCdnZnK0RSTm5tOXhQdTdpQ053WEZNcXhLL3Z5WkRQOFZjTkx4OHdPZHdZbERWTkJnbmNsZ3B3VVUzV29xSUt5RjQ0VTdmV04xTVJNbDlmR1FhN0FPdEt4bGtKOHZXZERQTXpZMDNKMXJyZldwQTBGWVNoTHpLb0FtQ0FFVE9udjZYazNxcXZtaDR0MVZBV1FzV29CRzhyV2huckdEYzZDQmwzTzM2Q0xKTzZxSnBYdlBvVU9RL0p6MFFlUmw2WU1ET1FJaTBucG5LZk9sVTVzblNIc2h6Mkg5dXhUSHZRWkdzOWQxeGZpakxncVFxci90d1pRS3ZzMEg4K1Q0eDFxNVYzVm52ZHJxSXovUlQ2WVFwMEM0NmJhQ2JydmVZYXNweS9ZLzNIUm91VTNJZkhFQTFQYy9EYTNuNS9nVEpjYy9QU2pYZE9VPC9jYmM6RW1iZWRkZWREb2N1bWVudEJpbmFyeU9iamVjdD48L2NhYzpBdHRhY2htZW50PjwvY2FjOkFkZGl0aW9uYWxEb2N1bWVudFJlZmVyZW5jZT48Y2FjOkFkZGl0aW9uYWxEb2N1bWVudFJlZmVyZW5jZT48Y2JjOklEPlFSPC9jYmM6SUQ+PGNhYzpBdHRhY2htZW50PjxjYmM6RW1iZWRkZWREb2N1bWVudEJpbmFyeU9iamVjdCBtaW1lQ29kZT0idGV4dC9wbGFpbiI+QVF4R2FYSnZlaUJCYzJoeVlXWUNDakV5TXpRMU5qYzRPVEVERXpJd01qRXRNVEV0TVRjZ01EZzZNekE2TURBRUJqRXdNQzR3TUFVRk1UVXVNREFHTEhOTVRqTlhTa2hQTVdsemNsSTViekZoVVdFNVUyRTFTWG92TUd4cVNFbEVORFZSVDFGMVJpdFJRbmM5Qi85bVFrVldTazl4VUVZMVpURlZUa0UwTXpNeVRqaE1jRUZCTDJ4MVdVOUJTemRSYlRGa04wNWpOSGhqV1RJclozSkliRXN3YWs1V1ZrWXJOWFZWT0hkM2VYWjBTR0Z1YjNJd1VYZzFjRFV5VjFRclZuUjVMMVZGYWtkcVF6QmpVa3MwT0RSUE1FRnhaVUp6T0ZoTlIxa3pkVWRyVWtFMFYxUm9ZWFpsTlhaTkswMUpVbkpLTmpJM01VTXZNRU13V2twek4wOVRSM2RCYjNkWmJsTm1Oa2h6VTJaTlNFZE1iRGd2UkZGSE5TOVhNalUzWldWeU1YUkZTMmd4U0hOdWEyZzRVbVpvY0V4UmRHeE1kR2sxZEhCb1VYaENhMGd5T1VSdE5YVmxhamxFTldkMlF6UldkSGRSTjBOVVNFSXJjSE0yTDBOU1ZEVjFkM05aY2tWTFNWZHZTMHBwTmtVMVMwVTJZa2RLV1ROUFVtMDJNVUpwVVVWRVZYUnFVR1V4ZERNM1FsSkJUMUZRVkc5aWFYSllaWGRJVGtSVFZsUTNSMngwY0ZkbFpFVkhZbU5KZFdVNFQxcFRlWEY0UVZST09Hd3lTQ3N5VFZFOVBRai9NSUlCQ2dLQ0FRRUF2VUk0azNhNy9Yb0JDYm04aHVsM3I4b3RPNE5yOUI0ZjhMejcxSjAzQjEyUlVUVWFMb0RWVmNiS0lCWk5MRmNnRlM0Q1hoR213RjNCZkRYRXd6NE8vTFhJOUxYZmNTR3JFTnAwVmhIbVFhb2JOeG5OS2lMKzVDRnkvem8xRXltSDY5dDJkVEZ4cFk5MmNnYWF0UUxKb2FBbVd5ckpHekthMGlyeHUxWFhFZlFsa2tvNjVOTnptTGc2eHZJaEpOREZFN2wxZGRQdTdzZlFGaTJYcC9DVGNVeTZ4MHNRRlZ5UTZNQmRKVlZ1WTFLelJoZzNFQk4vYS9ESERZVUxGU2hEOE1lK1ZYOTUvZC8yVDhuR3lXRVRqR0lFcElkNnprMHhiUk5heDVYcFhzQkR4ZjdxbEljaGFnTUNXUnMySDhQdDZ6Q1pqNVk3OWlSMUxMY2oyemVWYlFJREFRQUJDZjg5OEkwakhkaHZvbFBhQnZ2ZytEUk5ubTl4UHU3aUNOd1hGTXF4Sy92eVpEUDhWY05MeDh3T2R3WWxEVk5CZ25jbGdwd1VVM1dvcUlLeUY0NFU3ZldOMU1STWw5ZkdRYTdBT3RLeGxrSjh2V2REUE16WTAzSjFycmZXcEEwRllTaEx6S29BbUNBRVRPbnY2WGszcXF2bWg0dDFWQVdRc1dvQkc4cldobnJHRGM2Q0JsM08zNkNMSk82cUpwWHZQb1VPUS9KejBRZVJsNllNRE9RSWkwbnBuS2ZPbFU1c25TSHNoejJIOXV4VEh2UVpHczlkMXhmaWpMZ3FRcXIvdHdaUUt2czBIOCtUNHgxcTVWM1ZudmRycUl6L1JUNllRcDBDNDZiYUNicnZlWWFzcHkvWS8zSFJvdVUzSWZIRUExUGMvRGEzbjUvZ1RKY2MvUFNqWGRPVTwvY2JjOkVtYmVkZGVkRG9jdW1lbnRCaW5hcnlPYmplY3Q+PC9jYWM6QXR0YWNobWVudD48L2NhYzpBZGRpdGlvbmFsRG9jdW1lbnRSZWZlcmVuY2U+PGNhYzpBZGRpdGlvbmFsRG9jdW1lbnRSZWZlcmVuY2U+PGNiYzpJRD5RUjwvY2JjOklEPjxjYWM6QXR0YWNobWVudD48Y2JjOkVtYmVkZGVkRG9jdW1lbnRCaW5hcnlPYmplY3QgbWltZUNvZGU9InRleHQvcGxhaW4iPkFReEdhWEp2ZWlCQmMyaHlZV1lDQ2pFeU16UTFOamM0T1RFREV6SXdNakV0TVRFdE1UY2dNRGc2TXpBNk1EQUVCakV3TUM0d01BVUZNVFV1TURBR0xITk1Uak5YU2toUE1XbHpjbEk1YnpGaFVXRTVVMkUxU1hvdk1HeHFTRWxFTkRWUlQxRjFSaXRSUW5jOUIvOW1Ra1ZXU2s5eFVFWTFaVEZWVGtFME16TXlUamhNY0VGQkwyeDFXVTlCU3pkUmJURmtOMDVqTkhoaldUSXJaM0pJYkVzd2FrNVdWa1lyTlhWVk9IZDNlWFowU0dGdWIzSXdVWGcxY0RVeVYxUXJWblI1TDFWRmFrZHFRekJqVWtzME9EUlBNRUZ4WlVKek9GaE5SMWt6ZFVkclVrRTBWMVJvWVhabE5YWk5LMDFKVW5KS05qSTNNVU12TUVNd1drcHpOMDlUUjNkQmIzZFpibE5tTmtoelUyWk5TRWRNYkRndlJGRkhOUzlYTWpVM1pXVnlNWFJGUzJneFNITnVhMmc0VW1ab2NFeFJkR3hNZEdrMWRIQm9VWGhDYTBneU9VUnROWFZsYWpsRU5XZDJRelJXZEhkUk4wTlVTRUlyY0hNMkwwTlNWRFYxZDNOWmNrVkxTVmR2UzBwcE5rVTFTMFUyWWtkS1dUTlBVbTAyTVVKcFVVVkVWWFJxVUdVeGRETTNRbEpCVDFGUVZHOWlhWEpZWlhkSVRrUlRWbFEzUjJ4MGNGZGxaRVZIWW1OSmRXVTRUMXBUZVhGNFFWUk9PR3d5U0NzeVRWRTlQUWovTUlJQkNnS0NBUUVBdlVJNGszYTcvWG9CQ2JtOGh1bDNyOG90TzROcjlCNGY4THo3MUowM0IxMlJVVFVhTG9EVlZjYktJQlpOTEZjZ0ZTNENYaEdtd0YzQmZEWEV3ejRPL0xYSTlMWGZjU0dyRU5wMFZoSG1RYW9iTnhuTktpTCs1Q0Z5L3pvMUV5bUg2OXQyZFRGeHBZOTJjZ2FhdFFMSm9hQW1XeXJKR3pLYTBpcnh1MVhYRWZRbGtrbzY1Tk56bUxnNnh2SWhKTkRGRTdsMWRkUHU3c2ZRRmkyWHAvQ1RjVXk2eDBzUUZWeVE2TUJkSlZWdVkxS3pSaGczRUJOL2EvREhEWVVMRlNoRDhNZStWWDk1L2QvMlQ4bkd5V0VUakdJRXBJZDZ6azB4YlJOYXg1WHBYc0JEeGY3cWxJY2hhZ01DV1JzMkg4UHQ2ekNaajVZNzlpUjFMTGNqMnplVmJRSURBUUFCQ2Y4OThJMGpIZGh2b2xQYUJ2dmcrRFJObm05eFB1N2lDTndYRk1xeEsvdnlaRFA4VmNOTHg4d09kd1lsRFZOQmduY2xncHdVVTNXb3FJS3lGNDRVN2ZXTjFNUk1sOWZHUWE3QU90S3hsa0o4dldkRFBNelkwM0oxcnJmV3BBMEZZU2hMektvQW1DQUVUT252NlhrM3Fxdm1oNHQxVkFXUXNXb0JHOHJXaG5yR0RjNkNCbDNPMzZDTEpPNnFKcFh2UG9VT1EvSnowUWVSbDZZTURPUUlpMG5wbktmT2xVNXNuU0hzaHoySDl1eFRIdlFaR3M5ZDF4ZmlqTGdxUXFyL3R3WlFLdnMwSDgrVDR4MXE1VjNWbnZkcnFJei9SVDZZUXAwQzQ2YmFDYnJ2ZVlhc3B5L1kvM0hSb3VVM0lmSEVBMVBjL0RhM241L2dUSmNjL1BTalhkT1U8L2NiYzpFbWJlZGRlZERvY3VtZW50QmluYXJ5T2JqZWN0Pg0KIDwvY2FjOkF0dGFjaG1lbnQ+DQogPC9jYWM6QWRkaXRpb25hbERvY3VtZW50UmVmZXJlbmNlPg0KIA0KIDxjYWM6U2lnbmF0dXJlPg0KICAgICAgIDxjYmM6SUQ+dXJuOm9hc2lzOm5hbWVzOnNwZWNpZmljYXRpb246dWJsOnNpZ25hdHVyZTpJbnZvaWNlPC9jYmM6SUQ+DQogICAgICAgPGNiYzpTaWduYXR1cmVNZXRob2Q+dXJuOm9hc2lzOm5hbWVzOnNwZWNpZmljYXRpb246dWJsOmRzaWc6ZW52ZWxvcGVkOnhhZGVzPC9jYmM6U2lnbmF0dXJlTWV0aG9kPg0KIDwvY2FjOlNpZ25hdHVyZT48Y2FjOkFjY291bnRpbmdTdXBwbGllclBhcnR5Pg0KICAgICAgIDxjYWM6UGFydHk+DQogICAgICAgICAgPGNhYzpQYXJ0eUlkZW50aWZpY2F0aW9uPg0KICAgICAgICAgICAgIDxjYmM6SUQgc2NoZW1lSUQ9Ik1MUyI+MTIzNDU3ODkwPC9jYmM6SUQ+DQogICAgICAgICAgPC9jYWM6UGFydHlJZGVudGlmaWNhdGlvbj4NCiAgICAgICAgICA8Y2FjOlBvc3RhbEFkZHJlc3M+DQogICAgICAgICAgICAgPGNiYzpTdHJlZXROYW1lPktpbmcgQWJkdWxheml6IFJvYWQ8L2NiYzpTdHJlZXROYW1lPg0KICAgICAgICAgICAgIDxjYmM6QnVpbGRpbmdOdW1iZXI+OTk5OTwvY2JjOkJ1aWxkaW5nTnVtYmVyPg0KICAgICAgICAgICAgIDxjYmM6UGxvdElkZW50aWZpY2F0aW9uPjk5OTk8L2NiYzpQbG90SWRlbnRpZmljYXRpb24+DQogICAgICAgICAgICAgPGNiYzpDaXR5U3ViZGl2aXNpb25OYW1lPkFsIEFtYWw8L2NiYzpDaXR5U3ViZGl2aXNpb25OYW1lPg0KICAgICAgICAgICAgIDxjYmM6Q2l0eU5hbWU+Uml5YWRoPC9jYmM6Q2l0eU5hbWU+DQogICAgICAgICAgICAgPGNiYzpQb3N0YWxab25lPjEyNjQzPC9jYmM6UG9zdGFsWm9uZT4NCiAgICAgICAgICAgICA8Y2JjOkNvdW50cnlTdWJlbnRpdHk+Uml5YWRoIFJlZ2lvbjwvY2JjOkNvdW50cnlTdWJlbnRpdHk+DQogICAgICAgICAgICAgPGNhYzpDb3VudHJ5Pg0KICAgICAgICAgICAgICAgIDxjYmM6SWRlbnRpZmljYXRpb25Db2RlPlNBPC9jYmM6SWRlbnRpZmljYXRpb25Db2RlPg0KICAgICAgICAgICAgIDwvY2FjOkNvdW50cnk+DQogICAgICAgICAgPC9jYWM6UG9zdGFsQWRkcmVzcz4NCiAgICAgICAgICA8Y2FjOlBhcnR5VGF4U2NoZW1lPg0KICAgICAgICAgICAgIDxjYmM6Q29tcGFueUlEPjMwMDA5OTk5OTkwMDAwMzwvY2JjOkNvbXBhbnlJRD4NCiAgICAgICAgICAgICA8Y2FjOlRheFNjaGVtZT4NCiAgICAgICAgICAgICAgICA8Y2JjOklEPlZBVDwvY2JjOklEPg0KICAgICAgICAgICAgIDwvY2FjOlRheFNjaGVtZT4NCiAgICAgICAgICA8L2NhYzpQYXJ0eVRheFNjaGVtZT4NCiAgICAgICAgICA8Y2FjOlBhcnR5TGVnYWxFbnRpdHk+DQogICAgICAgICAgICAgPGNiYzpSZWdpc3RyYXRpb25OYW1lPkV4YW1wbGUgQ28uIExURDwvY2JjOlJlZ2lzdHJhdGlvbk5hbWU+DQogICAgICAgICAgPC9jYWM6UGFydHlMZWdhbEVudGl0eT4NCiAgICAgICA8L2NhYzpQYXJ0eT4NCiAgICA8L2NhYzpBY2NvdW50aW5nU3VwcGxpZXJQYXJ0eT4NCiAgICA8Y2FjOkFjY291bnRpbmdDdXN0b21lclBhcnR5Pg0KICAgICAgIDxjYWM6UGFydHk+DQogICAgICAgICAgPGNhYzpQYXJ0eUlkZW50aWZpY2F0aW9uPg0KICAgICAgICAgICAgIDxjYmM6SUQgc2NoZW1lSUQ9IlNBRyI+MTIzQzEyMzQ1Njc4PC9jYmM6SUQ+DQogICAgICAgICAgPC9jYWM6UGFydHlJZGVudGlmaWNhdGlvbj4NCiAgICAgICAgICA8Y2FjOlBvc3RhbEFkZHJlc3M+DQogICAgICAgICAgICAgPGNiYzpTdHJlZXROYW1lPktpbmcgQWJkdWxsYWggUm9hZDwvY2JjOlN0cmVldE5hbWU+DQogICAgICAgICAgICAgPGNiYzpCdWlsZGluZ051bWJlcj45OTk5PC9jYmM6QnVpbGRpbmdOdW1iZXI+DQogICAgICAgICAgICAgPGNiYzpQbG90SWRlbnRpZmljYXRpb24+OTk5OTwvY2JjOlBsb3RJZGVudGlmaWNhdGlvbj4NCiAgICAgICAgICAgICA8Y2JjOkNpdHlTdWJkaXZpc2lvbk5hbWU+QWwgTXVyc2FsYXQ8L2NiYzpDaXR5U3ViZGl2aXNpb25OYW1lPg0KICAgICAgICAgICAgIDxjYmM6Q2l0eU5hbWU+Uml5YWRoPC9jYmM6Q2l0eU5hbWU+DQogICAgICAgICAgICAgPGNiYzpQb3N0YWxab25lPjExNTY0PC9jYmM6UG9zdGFsWm9uZT4NCiAgICAgICAgICAgICA8Y2JjOkNvdW50cnlTdWJlbnRpdHk+Uml5YWRoIFJlZ2lvbjwvY2JjOkNvdW50cnlTdWJlbnRpdHk+DQogICAgICAgICAgICAgPGNhYzpDb3VudHJ5Pg0KICAgICAgICAgICAgICAgIDxjYmM6SWRlbnRpZmljYXRpb25Db2RlPlNBPC9jYmM6SWRlbnRpZmljYXRpb25Db2RlPg0KICAgICAgICAgICAgIDwvY2FjOkNvdW50cnk+DQogICAgICAgICAgPC9jYWM6UG9zdGFsQWRkcmVzcz4NCiAgICAgICAgICA8Y2FjOlBhcnR5VGF4U2NoZW1lPg0KICAgICAgICAgICAgIDxjYWM6VGF4U2NoZW1lPg0KICAgICAgICAgICAgICAgIDxjYmM6SUQ+VkFUPC9jYmM6SUQ+DQogICAgICAgICAgICAgPC9jYWM6VGF4U2NoZW1lPg0KICAgICAgICAgIDwvY2FjOlBhcnR5VGF4U2NoZW1lPg0KICAgICAgICAgIDxjYWM6UGFydHlMZWdhbEVudGl0eT4NCiAgICAgICAgICAgICA8Y2JjOlJlZ2lzdHJhdGlvbk5hbWU+RVhBTVBMRSBNQVJLRVRTPC9jYmM6UmVnaXN0cmF0aW9uTmFtZT4NCiAgICAgICAgICA8L2NhYzpQYXJ0eUxlZ2FsRW50aXR5Pg0KICAgICAgIDwvY2FjOlBhcnR5Pg0KICAgIDwvY2FjOkFjY291bnRpbmdDdXN0b21lclBhcnR5Pg0KICAgIDxjYWM6RGVsaXZlcnk+DQogICAgICAgPGNiYzpBY3R1YWxEZWxpdmVyeURhdGU+MjAyMi0wNC0yNTwvY2JjOkFjdHVhbERlbGl2ZXJ5RGF0ZT4NCiAgICA8L2NhYzpEZWxpdmVyeT4NCiAgICA8Y2FjOlBheW1lbnRNZWFucz4NCiAgICAgICA8Y2JjOlBheW1lbnRNZWFuc0NvZGU+NDI8L2NiYzpQYXltZW50TWVhbnNDb2RlPg0KICAgIDwvY2FjOlBheW1lbnRNZWFucz4NCiAgICA8Y2FjOlRheFRvdGFsPg0KICAgICAgIDxjYmM6VGF4QW1vdW50IGN1cnJlbmN5SUQ9IlNBUiI+MTM1LjAwPC9jYmM6VGF4QW1vdW50Pg0KICAgICAgIDxjYWM6VGF4U3VidG90YWw+DQogICAgICAgICAgPGNiYzpUYXhhYmxlQW1vdW50IGN1cnJlbmN5SUQ9IlNBUiI+OTAwLjAwPC9jYmM6VGF4YWJsZUFtb3VudD4NCiAgICAgICAgICA8Y2JjOlRheEFtb3VudCBjdXJyZW5jeUlEPSJTQVIiPjEzNS4wMDwvY2JjOlRheEFtb3VudD4NCiAgICAgICAgICA8Y2FjOlRheENhdGVnb3J5Pg0KICAgICAgICAgICAgIDxjYmM6SUQ+UzwvY2JjOklEPg0KICAgICAgICAgICAgIDxjYmM6UGVyY2VudD4xNTwvY2JjOlBlcmNlbnQ+DQogICAgICAgICAgICAgPGNhYzpUYXhTY2hlbWU+DQogICAgICAgICAgICAgICAgPGNiYzpJRD5WQVQ8L2NiYzpJRD4NCiAgICAgICAgICAgICA8L2NhYzpUYXhTY2hlbWU+DQogICAgICAgICAgPC9jYWM6VGF4Q2F0ZWdvcnk+DQogICAgICAgPC9jYWM6VGF4U3VidG90YWw+DQogICAgPC9jYWM6VGF4VG90YWw+DQogICAgPGNhYzpUYXhUb3RhbD4NCiAgICAgICA8Y2JjOlRheEFtb3VudCBjdXJyZW5jeUlEPSJTQVIiPjEzNS4wMDwvY2JjOlRheEFtb3VudD4NCiAgICA8L2NhYzpUYXhUb3RhbD4NCiAgICA8Y2FjOkxlZ2FsTW9uZXRhcnlUb3RhbD4NCiAgICAgICA8Y2JjOkxpbmVFeHRlbnNpb25BbW91bnQgY3VycmVuY3lJRD0iU0FSIj45MDAuMDA8L2NiYzpMaW5lRXh0ZW5zaW9uQW1vdW50Pg0KICAgICAgIDxjYmM6VGF4RXhjbHVzaXZlQW1vdW50IGN1cnJlbmN5SUQ9IlNBUiI+OTAwLjAwPC9jYmM6VGF4RXhjbHVzaXZlQW1vdW50Pg0KICAgICAgIDxjYmM6VGF4SW5jbHVzaXZlQW1vdW50IGN1cnJlbmN5SUQ9IlNBUiI+MTAzNS4wMDwvY2JjOlRheEluY2x1c2l2ZUFtb3VudD4NCiAgICAgICA8Y2JjOkFsbG93YW5jZVRvdGFsQW1vdW50IGN1cnJlbmN5SUQ9IlNBUiI+MC4wMDwvY2JjOkFsbG93YW5jZVRvdGFsQW1vdW50Pg0KICAgICAgIDxjYmM6UGF5YWJsZUFtb3VudCBjdXJyZW5jeUlEPSJTQVIiPjEwMzUuMDA8L2NiYzpQYXlhYmxlQW1vdW50Pg0KICAgIDwvY2FjOkxlZ2FsTW9uZXRhcnlUb3RhbD4NCiAgICA8Y2FjOkludm9pY2VMaW5lPg0KICAgICAgIDxjYmM6SUQ+MTwvY2JjOklEPg0KICAgICAgIDxjYmM6SW52b2ljZWRRdWFudGl0eSB1bml0Q29kZT0iUENFIj4xPC9jYmM6SW52b2ljZWRRdWFudGl0eT4NCiAgICAgICA8Y2JjOkxpbmVFeHRlbnNpb25BbW91bnQgY3VycmVuY3lJRD0iU0FSIj4yMDAuMDA8L2NiYzpMaW5lRXh0ZW5zaW9uQW1vdW50Pg0KICAgICAgIDxjYWM6VGF4VG90YWw+DQogICAgICAgICAgPGNiYzpUYXhBbW91bnQgY3VycmVuY3lJRD0iU0FSIj4zMC4wMDwvY2JjOlRheEFtb3VudD4NCiAgICAgICAgICA8Y2JjOlJvdW5kaW5nQW1vdW50IGN1cnJlbmN5SUQ9IlNBUiI+MjMwLjAwPC9jYmM6Um91bmRpbmdBbW91bnQ+DQogICAgICAgPC9jYWM6VGF4VG90YWw+DQogICAgICAgPGNhYzpJdGVtPg0KICAgICAgICAgIDxjYmM6TmFtZT5JdGVtIEE8L2NiYzpOYW1lPg0KICAgICAgICAgIDxjYWM6Q2xhc3NpZmllZFRheENhdGVnb3J5Pg0KICAgICAgICAgICAgIDxjYmM6SUQ+UzwvY2JjOklEPg0KICAgICAgICAgICAgIDxjYmM6UGVyY2VudD4xNTwvY2JjOlBlcmNlbnQ+DQogICAgICAgICAgICAgPGNhYzpUYXhTY2hlbWU+DQogICAgICAgICAgICAgICAgPGNiYzpJRD5WQVQ8L2NiYzpJRD4NCiAgICAgICAgICAgICA8L2NhYzpUYXhTY2hlbWU+DQogICAgICAgICAgPC9jYWM6Q2xhc3NpZmllZFRheENhdGVnb3J5Pg0KICAgICAgIDwvY2FjOkl0ZW0+DQogICAgICAgPGNhYzpQcmljZT4NCiAgICAgICAgICA8Y2JjOlByaWNlQW1vdW50IGN1cnJlbmN5SUQ9IlNBUiI+MjAwLjAwPC9jYmM6UHJpY2VBbW91bnQ+DQogICAgICAgPC9jYWM6UHJpY2U+DQogICAgPC9jYWM6SW52b2ljZUxpbmU+DQogICAgPGNhYzpJbnZvaWNlTGluZT4NCiAgICAgICA8Y2JjOklEPjI8L2NiYzpJRD4NCiAgICAgICA8Y2JjOkludm9pY2VkUXVhbnRpdHkgdW5pdENvZGU9IlBDRSI+MjwvY2JjOkludm9pY2VkUXVhbnRpdHk+DQogICAgICAgPGNiYzpMaW5lRXh0ZW5zaW9uQW1vdW50IGN1cnJlbmN5SUQ9IlNBUiI+NzAwLjAwPC9jYmM6TGluZUV4dGVuc2lvbkFtb3VudD4NCiAgICAgICA8Y2FjOlRheFRvdGFsPg0KICAgICAgICAgIDxjYmM6VGF4QW1vdW50IGN1cnJlbmN5SUQ9IlNBUiI+MTA1LjAwPC9jYmM6VGF4QW1vdW50Pg0KICAgICAgICAgIDxjYmM6Um91bmRpbmdBbW91bnQgY3VycmVuY3lJRD0iU0FSIj44MDUuMDA8L2NiYzpSb3VuZGluZ0Ftb3VudD4NCiAgICAgICA8L2NhYzpUYXhUb3RhbD4NCiAgICAgICA8Y2FjOkl0ZW0+DQogICAgICAgICAgPGNiYzpOYW1lPkl0ZW0gQjwvY2JjOk5hbWU+DQogICAgICAgICAgPGNhYzpDbGFzc2lmaWVkVGF4Q2F0ZWdvcnk+DQogICAgICAgICAgICAgPGNiYzpJRD5TPC9jYmM6SUQ+DQogICAgICAgICAgICAgPGNiYzpQZXJjZW50PjE1PC9jYmM6UGVyY2VudD4NCiAgICAgICAgICAgICA8Y2FjOlRheFNjaGVtZT4NCiAgICAgICAgICAgICAgICA8Y2JjOklEPlZBVDwvY2JjOklEPg0KICAgICAgICAgICAgIDwvY2FjOlRheFNjaGVtZT4NCiAgICAgICAgICA8L2NhYzpDbGFzc2lmaWVkVGF4Q2F0ZWdvcnk+DQogICAgICAgPC9jYWM6SXRlbT4NCiAgICAgICA8Y2FjOlByaWNlPg0KICAgICAgICAgIDxjYmM6UHJpY2VBbW91bnQgY3VycmVuY3lJRD0iU0FSIj4zNTAuMDA8L2NiYzpQcmljZUFtb3VudD4NCiAgICAgICA8L2NhYzpQcmljZT4NCiAgICA8L2NhYzpJbnZvaWNlTGluZT4NCiA8L0ludm9pY2U+"
})
headers = {
  'accept': 'application/json',
  'Accept-Language': 'en',
  'Accept-Version': 'V2',
  'Authorization': 'Basic VFVsSlJERnFRME5CTTNsblFYZEpRa0ZuU1ZSaWQwRkJaVFJUYUhOMmVXNDNNREo1VUhkQlFrRkJRamRvUkVGTFFtZG5jV2hyYWs5UVVWRkVRV3BDYWsxU1ZYZEZkMWxMUTFwSmJXbGFVSGxNUjFGQ1IxSlpSbUpIT1dwWlYzZDRSWHBCVWtKbmIwcHJhV0ZLYXk5SmMxcEJSVnBHWjA1dVlqTlplRVo2UVZaQ1oyOUthMmxoU21zdlNYTmFRVVZhUm1ka2JHVklVbTVaV0hBd1RWSjNkMGRuV1VSV1VWRkVSWGhPVlZVeGNFWlRWVFZYVkRCc1JGSlRNVlJrVjBwRVVWTXdlRTFDTkZoRVZFbDVUVVJaZUUxNlJURk5la1V3VG14dldFUlVTVEJOUkZsNFRXcEZNVTE2UlRCT2JHOTNVMVJGVEUxQmEwZEJNVlZGUW1oTlExVXdSWGhFYWtGTlFtZE9Wa0pCYjFSQ1YwWnVZVmQ0YkUxU1dYZEdRVmxFVmxGUlRFVjNNVzlaV0d4b1NVaHNhRm95YUhSaU0xWjVUVkpKZDBWQldVUldVVkZFUlhkcmVFMXFZM1ZOUXpSM1RHcEZkMVpxUVZGQ1oyTnhhR3RxVDFCUlNVSkNaMVZ5WjFGUlFVTm5Ua05CUVZSVVFVczViSEpVVm10dk9YSnJjVFphV1dOak9VaEVVbHBRTkdJNVV6UjZRVFJMYlRkWldFb3JjMjVVVm1oTWEzcFZNRWh6YlZOWU9WVnVPR3BFYUZKVVQwaEVTMkZtZERoREwzVjFWVms1TXpSMmRVMU9ielJKUTB0cVEwTkJhVmwzWjFselIwRXhWV1JGVVZOQ1ozcERRbWRMVWl0TlNIZDRTRlJCWWtKblRsWkNRVkZOUmtSRmRHRkhSalZaV0hkNVRGUkplazVJZDNwTVZFVjRUV3BOZWsxU09IZElVVmxMUTFwSmJXbGFVSGxNUjFGQ1FWRjNVRTE2VFhoTlZGbDVUMFJaTlU1RVFYZE5SRUY2VFZFd2QwTjNXVVJXVVZGTlJFRlJlRTFVUVhkTlVrVjNSSGRaUkZaUlVXRkVRV2hoV1ZoU2FsbFRRWGhOYWtWWlRVSlpSMEV4VlVWRWQzZFFVbTA1ZGxwRFFrTmtXRTU2WVZjMWJHTXpUWHBOUWpCSFFURlZaRVJuVVZkQ1FsTm5iVWxYUkRaaVVHWmlZa3RyYlZSM1QwcFNXSFpKWWtnNVNHcEJaa0puVGxaSVUwMUZSMFJCVjJkQ1VqSlpTWG8zUW5GRGMxb3hZekZ1WXl0aGNrdGpjbTFVVnpGTWVrSlBRbWRPVmtoU09FVlNla0pHVFVWUFoxRmhRUzlvYWpGdlpFaFNkMDlwT0haa1NFNHdXVE5LYzB4dWNHaGtSMDVvVEcxa2RtUnBOWHBaVXpsRVdsaEtNRkpYTlhsaU1uaHpUREZTVkZkclZrcFViRnBRVTFWT1JreFdUakZaYTA1Q1RGUkZkVmt6U25OTlNVZDBRbWRuY2tKblJVWkNVV05DUVZGVFFtOUVRMEp1VkVKMVFtZG5ja0puUlVaQ1VXTjNRVmxhYVdGSVVqQmpSRzkyVEROU2VtUkhUbmxpUXpVMldWaFNhbGxUTlc1aU0xbDFZekpGZGxFeVZubGtSVloxWTIwNWMySkRPVlZWTVhCR1lWYzFNbUl5YkdwYVZrNUVVVlJGZFZwWWFEQmFNa1kyWkVNMWJtSXpXWFZpUnpscVdWZDRabFpHVG1GU1ZXeFBWbXM1U2xFd1ZYUlZNMVpwVVRCRmRFMVRaM2hMVXpWcVkyNVJkMHQzV1VsTGQxbENRbEZWU0UxQlIwZElNbWd3WkVoQk5reDVPVEJqTTFKcVkyMTNkV1Z0UmpCWk1rVjFXakk1TWt4dVRtaE1NamxxWXpOQmQwUm5XVVJXVWpCUVFWRklMMEpCVVVSQloyVkJUVUl3UjBFeFZXUktVVkZYVFVKUlIwTkRjMGRCVVZWR1FuZE5RMEpuWjNKQ1owVkdRbEZqUkVGNlFXNUNaMnR5UW1kRlJVRlpTVE5HVVc5RlIycEJXVTFCYjBkRFEzTkhRVkZWUmtKM1RVTk5RVzlIUTBOelIwRlJWVVpDZDAxRVRVRnZSME5EY1VkVFRUUTVRa0ZOUTBFd1owRk5SVlZEU1ZGRVQxQXdaakJFY21oblpVUlVjbFpNZEVwMU9HeFhhelJJU25SbFkyWTFabVpsVWt4blpVUTRZMlZWWjBsblpFSkNUakl4U1RNM2FYTk5PVlZ0VTFGbE9IaFNjRWh1ZDA5NFNXYzNkMDR6V1RKMlZIQnpVR2hhU1QwPTpFcGo2OUdoOFRNTXpZZktsdEx2MW9tWktyaWUwc1A2TEF2YW1iUUZIVGd3PQ==',
  'Content-Type': 'application/json',
  'Cookie': 'TS0106293e=0132a679c0e485ac883c80675be0daa0e4cbdb9f2b8d3437da72f1d8702f3d15fbad03d69bdda95c426a73861f9298d914b129a6f3; TS0106293e=0132a679c02e4dd2149e7c95b2e7ceb9b1cfc434d73f56c79aec4e01ecc274791510243acbdc3dec6d86b7c4ece658f9b89ee766d7'
}

response = requests.request("POST", url, headers=headers, data=payload)

print(response.text)
