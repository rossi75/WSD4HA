# contains the templates used for the requests

# TEMPLATE_SOAP_PROBE
# provides a SOAP probe to a probably scanner
#
# Parameters:
# msg_id = Message ID

TEMPLATE_SOAP_PROBE = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope
  xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
  xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
  xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">
  <soap:Header>
    <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
    <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>
    <wsa:MessageID>urn:uuid:{msg_id}</wsa:MessageID>
  </soap:Header>
  <soap:Body>
    <wsd:Probe/>
  </soap:Body>
</soap:Envelope>
"""

# TEMPLATE_SOAP_TRANSFER_GET
# provides a SOAP TRANSFER/GET request to the scanner
#
# Parameters:
# to_device_uuid = scanners endpoint UUID
# msg_id = Message ID
# from_uuid = WSD4HAs UUID

TEMPLATE_SOAP_TRANSFER_GET = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">
  <soap:Header>
    <wsa:To>urn:uuid:{to_device_uuid}</wsa:To>
    <wsa:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/Get</wsa:Action>
    <wsa:MessageID>urn:uuid:{msg_id}</wsa:MessageID>
    <wsa:ReplyTo>
      <wsa:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>
    </wsa:ReplyTo>
    <wsa:From>
      <wsa:Address>urn:uuid:{from_uuid}</wsa:Address>
    </wsa:From>
  </soap:Header>
  <soap:Body/>
</soap:Envelope>
"""


# TEMPLATE_SUBSCRIBE_SAE
# SAE = ScanAvailableEvents
# provides a template to subscribe to a service
#
# Parameters:
# to_device_uuid = scanners endpoint UUID
# msg_id = Message ID
# xaddr = serviceadress  ==>  <wsa:To>http://192.168.0.3:8018/wsd/scan</wsa:To>
# from_uuid = WSD4HAs UUID
# EndTo_addr = adress that needs to be reachable by the scanner  ==>  <wsa:Address>http://192.168.0.1:5357/6ccf7716-4dc8-47bf-aca4-5a2ae5a959ca</wsa:Address>
# scan_to_name = Option selected by the user to start the scanning  ==>  "Scan to Home Assistant"
# Ref_ID = one more senseless ID  ==>  <wse:Identifier>urn:uuid:680be7cf-bc5a-409d-ad1d-4d6d96b5cb4f</wse:Identifier>

#TEMPLATE_SUBSCRIBE_ScanAvailableEvents = """<?xml version="1.0" encoding="utf-8"?>
TEMPLATE_SUBSCRIBE_SAE = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
               xmlns:wse="http://schemas.xmlsoap.org/ws/2004/08/eventing"
               xmlns:sca="http://schemas.microsoft.com/windows/2006/08/wdp/scan">
  <soap:Header>
    <wsa:To>{xaddr}</wsa:To>
    <wsa:Action>http://schemas.xmlsoap.org/ws/2004/08/eventing/Subscribe</wsa:Action>
    <wsa:MessageID>urn:uuid:{msg_id}</wsa:MessageID>
    <wsa:ReplyTo>
      <wsa:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>
    </wsa:ReplyTo>
    <wsa:From>
      <wsa:Address>urn:uuid:{from_uuid}</wsa:Address>
    </wsa:From>
  </soap:Header>
  <soap:Body>
    <wse:Subscribe>
      <wse:EndTo>
        <wsa:Address>{EndTo_addr}</wsa:Address>
        <wsa:ReferenceParameters>
          <wse:Identifier>urn:uuid:{Ref_ID}</wse:Identifier>
        </wsa:ReferenceParameters>
      </wse:EndTo>
      <wse:Delivery
        Mode="http://schemas.xmlsoap.org/ws/2004/08/eventing/DeliveryModes/Push">
        <wse:NotifyTo>
          <wsa:Address>{EndTo_addr}</wsa:Address>
          <wsa:ReferenceParameters>
            <wse:Identifier>urn:uuid:{Ref_ID}</wse:Identifier>
          </wsa:ReferenceParameters>
        </wse:NotifyTo>
      </wse:Delivery>
      <wse:Expires>
        PT1H
      </wse:Expires>
      <wse:Filter
        Dialect="http://schemas.xmlsoap.org/ws/2006/02/devprof/Action">
        http://schemas.microsoft.com/windows/2006/08/wdp/scan/ScanAvailableEvent
      </wse:Filter>
      <sca:ScanDestinations>
        <sca:ScanDestination>
          <sca:ClientDisplayName>{scan_to_name}</sca:ClientDisplayName>
          <sca:ClientContext>Scan</sca:ClientContext>
        </sca:ScanDestination>
      </sca:ScanDestinations>
    </wse:Subscribe>
  </soap:Body>
</soap:Envelope>
"""


TEMPLATE_SUBSCRIBE_RENEW = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
               xmlns:wse="http://schemas.xmlsoap.org/ws/2004/08/eventing"
               xmlns:sca="http://schemas.microsoft.com/windows/2006/08/wdp/scan">
  <soap:Header>
    <wsa:To>{xaddr}</wsa:To>
    <wsa:Action>http://schemas.xmlsoap.org/ws/2004/08/eventing/Renew</wsa:Action>
    <wsa:MessageID>urn:uuid:{msg_id}</wsa:MessageID>
    <wsa:ReplyTo>
      <wsa:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>
    </wsa:ReplyTo>
    <wsa:From>
      <wsa:Address>urn:uuid:{from_uuid}</wsa:Address>
    </wsa:From>
    <wse:Identifier>urn:uuid:{Ref_ID}</wse:Identifier>
  </soap:Header>
  <soap:Body>
    <wse:Renew>
      <wse:Expires>
        PT1H
      </wse:Expires>
    </wse:Renew>
  </soap:Body>
</soap:Envelope>
"""
