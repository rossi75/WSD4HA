
## __Global variables__
| Tupel           | Data Type   | Description           |
|-----------------|:-----------:|-----------------------|
| LOG_LEVEL       |    String   |                       |
| STARTUP_DT      | DateTime    |                       |
| SCANNERS        | Dictionary  | See description below |
| SCAN_JOBS       | Dictionary  | See description below |
| USER_AGENT      | String      | "Home Assistant"      |
| FROM_UUID       | UUID-String |                       |
| SCAN_FOLDER     | String      |                       |
| HTTP_PORT       | String      | default-value = 8110  |
| NOTIFY_PORT     | URL-String  | default-value = 5357  |
| LOCAL_IP        | IP          |                       |
| DISPLAY         | String      | ??                    |
| OFFLINE_TIMEOUT | Integer     |                       |

## __SCANNERS[uuid].__
| Tupel                           | Data Type   | Description      |
|---------------------------------|:-----------:|------------------|
| uuid                            | UUID-String |                  |
| ip                              | String      | IP Adress        |
| __WSD Parameters__              |             |                  |
| subscription_timeout            | Integer     |                  |
| subscription_last_seen          | DateTime    |                  |
| subscription_id                 | UUID-String |                  |
| subscription_ref                | String      |                  |
| destination_token               | String      |                  |
| end_to_addr                     | URL-String  |                  |
| __additional optional Details__ |             |                  |
| friendly_name                   | String      |                  |
| mac                             | String      |                  |
| firmware                        | String      |                  |
| serial                          | String      |                  |
| model                           | String      |                  |
| manufacturer                    | String      |                  |
| related_uuids                   | UUIDs       |                  |
| _ScanTicket_Dialect             | String      | [SIMPLE\|DETAIL] |
| __State__                       |             |                  |
| pinned                          | Boolean     |                  |
| first_seen                      | DateTime    |                  |
| last_seen                       | DateTime    |                  |
| state                           | switch      |                  |
| offline_since                   | DateTime    |                  |
| remove_after                    | DateTime    |                  |

| SCANNER.function      | parameter  | purpose                       |
|-----------------------|------------|-------------------------------|
| update()              | from self. | update last-seen timestamp    |
| update_subscription() | from self. | update subscription timestamp |
| mark_as_offline()     | from self. | remove from list              |
| pin_scanner()         | from self. | pin scanner to list           |
| unpin_scanner()       | from self. | unpin scanner from list       |


## __SCAN_JOBS[scanjob_identifier].__
| Tupel                           | Data Type   | Description          |
|---------------------------------|:-----------:|----------------------|
| scanjob_identifier              |    String   |                      |
| job_id                          | String      |                      |
| job_token                       | String      |                      |
| input_source                    | String      |                      |
| scan_from_uuid                  | UUID-String |                      |
| subscription_identifier         | String      |                      |
| xaddr                           | URL-String  |                      |
| destination_token               | String      |                      |
| state                           | String      |                      |
| job_created                     | DateTime    |                      |
| job_finished                    | DateTime    |                      |
| remove_after                    | DateTime    |                      |
| __Document related parameters__ |             |                      |
| DocPar_FileFormat               | String      | default-value 'jfif' |
| DocPar_ImagesToTransfer         | Integer     | always 1             |
| DocPar_InputSource              | String      | from job-description |
| DocPar_InputWidth               | Integer     | from job-description |
| DocPar_InputHeight              | Integer     | from job-description |
| DocPar_ResolutionWidth          | Integer     | from job-description |
| DocPar_ResolutionHeight         | Integer     | from job-description |
| DocPar_ExposureContrast         | Integer     | always 0             |
| DocPar_ExposureBrightness       | Integer     | always 0             |
| DocPar_ScalingWidth             | Integer     | always 100           |
| DocPar_ScalingHeight            | Integer     | always 100           |
| DocPar_Rotation                 | Integer     | always 0             |
| DocPar_RegionXOffset            | Integer     | always 0             |
| DocPar_RegionYOffset            | Integer     | always 0             |
| DocPar_RegionWidth              | Integer     | from job-description |
| DocPar_RegionHeight             | Integer     | from job-description |
| DocPar_ColorProcessing          | Integer     | always 'RGB24'       |
| DocPar_PixelsPerLine            | Integer     |                      |
| DocPar_NumberOfLines            | Integer     |                      |
| DocPar_BytesPerLine             | Integer     | always ""            |
| __Finalized__                   |             |                      |
| document                        | Byte[]      | the document itself  |
| filepath                        | String      | file location        |
