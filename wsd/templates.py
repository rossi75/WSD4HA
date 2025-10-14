# contains the templates used for the requests

################################################################################
# TEMPLATE_SOAP_PROBE
# provides a SOAP probe to a probably scanner
# ---------------------------------------------------------------------------------
# Parameters:
# msg_id = Message ID
# ---------------------------------------------------------------------------------
TEMPLATE_PROBE = """<?xml version="1.0" encoding="utf-8"?>
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

################################################################################
# TEMPLATE_SOAP_TRANSFER_GET
# provides a SOAP TRANSFER/GET request to the scanner
# ---------------------------------------------------------------------------------
# Parameters:
# to_device_uuid = scanners endpoint UUID
# msg_id = Message ID
# from_uuid = WSD4HAs UUID
# ---------------------------------------------------------------------------------
TEMPLATE_TRANSFER_GET = """<?xml version="1.0" encoding="utf-8"?>
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

################################################################################
# TEMPLATE_SUBSCRIBE_SAE
# SAE = ScanAvailableEvents
# provides a template to subscribe to a service
# ---------------------------------------------------------------------------------
# Parameters:
# xaddr = serviceadress  ==>  <wsa:To>http://192.168.0.3:8018/wsd/scan</wsa:To>
# msg_id = Message ID
# from_uuid = WSD4HAs UUID
# ---------------------------------------------------------------------------------
# EndTo_addr = adress that needs to be reachable by the scanner  ==>  <wsa:Address>http://192.168.0.1:5357/6ccf7716-4dc8-47bf-aca4-5a2ae5a959ca</wsa:Address>
# Ref_ID = one more senseless ID  ==>  <wse:Identifier>urn:uuid:680be7cf-bc5a-409d-ad1d-4d6d96b5cb4f</wse:Identifier>
# scan_to_name = Option selected by the user to start the scanning  ==>  "Scan to Home Assistant"

# to_device_uuid = scanners endpoint UUID --> wo is n der abgeblieben?
# ---------------------------------------------------------------------------------
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
      <wse:Expires>PT1H</wse:Expires>
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


###################################################################################
# TEMPLATE_SUBSCRIBE_RENEW
# ---------------------------------------------------------------------------------
# xaddr = destination adress
# msg_id = random message ID
# from_uuid = sender UUID
# Ref_ID = Reference UUID from subscribing
# ---------------------------------------------------------------------------------
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
    <wse:Identifier>{Ref_ID}</wse:Identifier>
  </soap:Header>
  <soap:Body>
    <wse:Renew>
      <wse:Expires>PT1H</wse:Expires>
    </wse:Renew>
  </soap:Body>
</soap:Envelope>
"""


################################################################################
# TEMPLATE_GET_SCANNER_ELEMENTS_STATE
# ---------------------------------------------------------------------------------
# xaddr = destination adress
# msg_id = random message ID
# from_uuid = sender UUID
# ---------------------------------------------------------------------------------
TEMPLATE_GET_SCANNER_ELEMENTS_STATE = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope
    xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
    xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
    xmlns:sca="http://schemas.microsoft.com/windows/2006/08/wdp/scan">
    <soap:Header>
        <wsa:To>{xaddr}</wsa:To>
        <wsa:Action>http://schemas.microsoft.com/windows/2006/08/wdp/scan/GetScannerElements</wsa:Action>
        <wsa:MessageID>urn:uuid:{msg_id}</wsa:MessageID>
        <wsa:From>
            <wsa:Address>urn:uuid:{from_uuid}</wsa:Address>
            </wsa:From>
        </soap:Header>
        <wsa:ReplyTo>
            <wsa:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>
            </wsa:ReplyTo>
    <soap:Body>
        <sca:GetScannerElementsRequest>
            <sca:RequestedElements>
                <sca:Name>sca:ScannerStatus</sca:Name>
                </sca:RequestedElements>
            </sca:GetScannerElementsRequest>
        </soap:Body>
    </soap:Envelope>
"""

################################################################################
# TEMPLATE_GET_SCANNER_ELEMENTS_DEFAULT_TICKET
# ---------------------------------------------------------------------------------
# xaddr = destination adress
# msg_id = random message ID
# from_uuid = sender UUID
# ---------------------------------------------------------------------------------
TEMPLATE_GET_SCANNER_ELEMENTS_DEFAULT_TICKET = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope
    xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
    xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
    xmlns:sca="http://schemas.microsoft.com/windows/2006/08/wdp/scan">
    <soap:Header>
        <wsa:To>{xaddr}</wsa:To>
        <wsa:Action>http://schemas.microsoft.com/windows/2006/08/wdp/scan/GetScannerElements</wsa:Action>
        <wsa:MessageID>urn:uuid:{msg_id}</wsa:MessageID>
        <wsa:From>
            <wsa:Address>urn:uuid:{from_uuid}</wsa:Address>
            </wsa:From>
        </soap:Header>
    <soap:Body>
        <sca:GetScannerElementsRequest>
            <sca:RequestedElements>
                <sca:Name>sca:DefaultScanTicket</sca:Name>
                </sca:RequestedElements>
            </sca:GetScannerElementsRequest>
        </soap:Body>
    </soap:Envelope>
"""

################################################################################
# TEMPLATE_SOAP_VALIDATE_SCAN_TICKET
# ---------------------------------------------------------------------------------
# xaddr = destination adress
# msg_id = random message ID
# from_uuid = sender UUID
# Ref_ID = Reference UUID from subscribing
# ---------------------------------------------------------------------------------
# Document Parameters, what and how to scan
# DocPar_format
# input_source
# DocPar_width
# DocPar_height
# DocPar_contrast
# DocPar_brightness
# DocPar_scan_width
# DocPar_scan_height
# DocPar_dpi_width
# DocPar_dpi_height
# ---------------------------------------------------------------------------------
TEMPLATE_VALIDATE_SCAN_TICKET_DETAIL = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope
 xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
 xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
 xmlns:sca="http://schemas.microsoft.com/windows/2006/08/wdp/scan">
  <soap:Header>
    <wsa:To>{to_addr}</wsa:To>
    <wsa:Action>http://schemas.microsoft.com/windows/2006/08/wdp/scan/ValidateScanTicket</wsa:Action>
    <wsa:MessageID>urn:uuid:{msg_id}</wsa:MessageID>
    <wsa:ReplyTo>
      <wsa:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>
    </wsa:ReplyTo>
    <wsa:From>
      <wsa:Address>urn:uuid:{from_uuid}</wsa:Address>
    </wsa:From>
  </soap:Header>
  <soap:Body>
    <sca:ValidateScanTicketRequest>
      <sca:ScanTicket>
        <sca:JobDescription>
          <sca:JobName>Altbier</sca:JobName>
          <sca:JobOriginatingUserName>Schnitzel</sca:JobOriginatingUserName>
          <sca:JobInformation>Pommes</sca:JobInformation>
        </sca:JobDescription>
        <sca:DocumentParameters>
          <sca:Format sca:MustHonor="true">{DocPar_format}</sca:Format>
          <sca:ImagesToTransfer sca:MustHonor="true">1</sca:ImagesToTransfer>
          <sca:InputSource sca:MustHonor="true">{input_source}</sca:InputSource>
          <sca:InputSize sca:MustHonor="true">
            <sca:InputMediaSize>
              <sca:Width>{DocPar_width}</sca:Width>
              <sca:Height>{DocPar_height}</sca:Height>
            </sca:InputMediaSize>
          </sca:InputSize>
          <sca:Exposure sca:MustHonor="true">
            <sca:ExposureSettings>
              <sca:Contrast>{DocPar_contrast}</sca:Contrast>
              <sca:Brightness>{DocPar_brightness}</sca:Brightness>
            </sca:ExposureSettings>
          </sca:Exposure>
          <sca:Scaling sca:MustHonor="true">
            <sca:ScalingWidth>100</sca:ScalingWidth>
            <sca:ScalingHeight>100</sca:ScalingHeight>
          </sca:Scaling>
          <sca:Rotation sca:MustHonor="true">0</sca:Rotation>
          <sca:MediaSides>
            <sca:MediaFront>
              <sca:ScanRegion>
                <sca:ScanRegionXOffset>0</sca:ScanRegionXOffset>
                <sca:ScanRegionYOffset>0</sca:ScanRegionYOffset>
                <sca:ScanRegionWidth>{DocPar_scan_width}</sca:ScanRegionWidth>
                <sca:ScanRegionHeight>{DocPar_scan_height}</sca:ScanRegionHeight>
              </sca:ScanRegion>
              <sca:ColorProcessing sca:MustHonor="true">RGB24</sca:ColorProcessing>
              <sca:Resolution sca:MustHonor="true">
                <sca:Width>{DocPar_dpi_width}</sca:Width>
                <sca:Height>{DocPar_dpi_height}</sca:Height>
              </sca:Resolution>
            </sca:MediaFront>
          </sca:MediaSides>
        </sca:DocumentParameters>
      </sca:ScanTicket>
    </sca:ValidateScanTicketRequest>
  </soap:Body>
</soap:Envelope>
"""


###################################################################################
# TEMPLATE_CREATE_SCANJOB
# ---------------------------------------------------------------------------------
# xaddr = destination adress
# msg_id = random message ID
# from_uuid = sender UUID
# scan_identifier = Scan Identifier from xml notification dialog
# destination_token = token given by scanner while registration
# ---------------------------------------------------------------------------------
# Document Parameters, what and how to scan
# DocPar_FileFormat
# DocPar_ImagesToTransfer
# DocPar_InputSource
# DocPar_InputWidth
# DocPar_InputHeight
# DocPar_RegionWidth
# DocPar_RegionHeight
# DocPar_ResolutionWidth
# DocPar_ResolutionHeight
# DocPar_ExposureContrast
# DocPar_ExposureBrightness
# DocPar_ScalingWidth
# DocPar_ScalingHeight
# DocPar_Rotation
# DocPar_RegionXOffset
# DocPar_RegionYOffset
# DocPar_ColorProcessing
# ---------------------------------------------------------------------------------
TEMPLATE_CREATE_SCANJOB = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
               xmlns:sca="http://schemas.microsoft.com/windows/2006/08/wdp/scan">
  <soap:Header>
    <wsa:To>{xaddr}</wsa:To>
    <wsa:Action>http://schemas.microsoft.com/windows/2006/08/wdp/scan/CreateScanJob</wsa:Action>
    <wsa:MessageID>urn:uuid:{msg_id}</wsa:MessageID>
    <wsa:ReplyTo>
        <wsa:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>
        </wsa:ReplyTo>
    <wsa:From>
        <wsa:Address>urn:uuid:{from_uuid}</wsa:Address>
        </wsa:From>
    </soap:Header>
<soap:Body>
    <sca:CreateScanJobRequest>
        <sca:ScanIdentifier>{scan_identifier}</sca:ScanIdentifier>
        <sca:DestinationToken>{destination_token}</sca:DestinationToken>
        <sca:ScanTicket>
            <sca:JobDescription>
                <sca:JobName>Validating scan ticket</sca:JobName>
                <sca:JobOriginatingUserName>Session for HomeAssistant</sca:JobOriginatingUserName>
                <sca:JobInformation>Scanning from platen..</sca:JobInformation>
                </sca:JobDescription>
            <sca:DocumentParameters>
                <sca:Format
                    sca:MustHonor="true">
                    {DocPar_FileFormat}
                    </sca:Format>
                <sca:ImagesToTransfer
                    sca:MustHonor="true">
                    {DocPar_ImagesToTransfer}
                    </sca:ImagesToTransfer>
                <sca:InputSource
                    sca:MustHonor="true">
                    {DocPar_InputSource}
                    </sca:InputSource>
                <sca:InputSize
                    sca:MustHonor="true">
                    <sca:InputMediaSize>
                        <sca:Width>{DocPar_InputWidth}</sca:Width>
                        <sca:Height>{DocPar_InputHeight}</sca:Height>
                        </sca:InputMediaSize>
                    </sca:InputSize>
                <sca:Exposure
                    sca:MustHonor="true">
                        <sca:ExposureSettings>
                        <sca:Contrast>{DocPar_ExposureContrast}</sca:Contrast>
                        <sca:Brightness>{DocPar_ExposureBrightness}</sca:Brightness>
                        </sca:ExposureSettings>
                    </sca:Exposure>
                <sca:Scaling
                    sca:MustHonor="true">
                    <sca:ScalingWidth>{DocPar_ScalingWidth}</sca:ScalingWidth>
                    <sca:ScalingHeight>{DocPar_ScalingHeight}</sca:ScalingHeight>
                    </sca:Scaling>
                <sca:Rotation
                    sca:MustHonor="true">
                    {DocPar_Rotation}
                    </sca:Rotation>
                <sca:MediaSides>
                    <sca:MediaFront>
                        <sca:ScanRegion>
                            <sca:ScanRegionXOffset
                                sca:MustHonor="true">
                                {DocPar_RegionXOffset}
                                </sca:ScanRegionXOffset>
                            <sca:ScanRegionYOffset
                                sca:MustHonor="true">
                                {DocPar_RegionYOffset}
                                </sca:ScanRegionYOffset>
                            <sca:ScanRegionWidth>{DocPar_RegionWidth}</sca:ScanRegionWidth>
                            <sca:ScanRegionHeight>{DocPar_RegionHeight}</sca:ScanRegionHeight>
                            </sca:ScanRegion>
                        <sca:ColorProcessing
                            sca:MustHonor="true">
                            {DocPar_ColorProcessing}
                            </sca:ColorProcessing>
                        <sca:Resolution
                            sca:MustHonor="true">
                            <sca:Width>{DocPar_ResolutionWidth}</sca:Width>
                            <sca:Height>{DocPar_ResolutionHeight}</sca:Height>
                            </sca:Resolution>
                        </sca:MediaFront>
                    </sca:MediaSides>
                </sca:DocumentParameters>
            </sca:ScanTicket>
        </sca:CreateScanJobRequest>
    </soap:Body>
</soap:Envelope>
"""

###################################################################################
# TEMPLATE_RETRIEVE_DOCUMENT
# fetches the document itself
# ---------------------------------------------------------------------------------
# xaddr = destination adress
# msg_id = random message ID
# ---------------------------------------------------------------------------------
# scan_identifier = Scan Identifier from xml notification dialog
# ---------------------------------------------------------------------------------
_TEMPLATE_RETRIEVE_DOCUMENT = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
               xmlns:wscn="http://schemas.microsoft.com/windows/2006/08/wdp/scan">
  <soap:Header>
    <wsa:To>http://{xaddr}</wsa:To>
    <wsa:Action>http://schemas.microsoft.com/windows/2006/08/wdp/scan/RetrieveImage</wsa:Action>
    <wsa:MessageID>urn:uuid:{msg_id}</wsa:MessageID>
  </soap:Header>
  <soap:Body>
    <wscn:RetrieveImageRequest>
      <wscn:ScanIdentifier>{scan_identifier}</wscn:ScanIdentifier>
    </wscn:RetrieveImageRequest>
  </soap:Body>
</soap:Envelope>
"""


###################################################################################
# TEMPLATE_RETRIEVE_DOCUMENT
# fetches the document itself
# ---------------------------------------------------------------------------------
# xaddr = destination adress
# msg_id = random message ID
# from_uuid = sender UUID
# ---------------------------------------------------------------------------------
# JobID = JobID from scanner through Scan Identifier
# JobToken = JobToken from scanner through Scan Identifier
# ---------------------------------------------------------------------------------
TEMPLATE_RETRIEVE_DOCUMENT = """<?xml version="1.0" encoding="utf-8"?>
    <soap:Envelope
        xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
        xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
        xmlns:sca="http://schemas.microsoft.com/windows/2006/08/wdp/scan">
        <soap:Header>
            <wsa:To>{xaddr}</wsa:To>
            <wsa:Action>http://schemas.microsoft.com/windows/2006/08/wdp/scan/RetrieveImage</wsa:Action>
            <wsa:MessageID>urn:uuid:{msg_id}</wsa:MessageID>
            <wsa:ReplyTo>
                <wsa:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>
                </wsa:ReplyTo>
            <wsa:From><wsa:Address>urn:uuid:{from_uuid}</wsa:Address></wsa:From>
            </soap:Header>
        <soap:Body>
            <sca:RetrieveImageRequest>
                <sca:JobId>{JobID}</sca:JobId>
                <sca:JobToken>{JobToken}</sca:JobToken>
                <sca:DocumentDescription>
                    <sca:DocumentName>Scanned image</sca:DocumentName>
                    </sca:DocumentDescription>
                </sca:RetrieveImageRequest>
            </soap:Body>
        </soap:Envelope>
"""
