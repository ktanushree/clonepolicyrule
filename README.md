# CloudGenix Clone Policy Rule (Preview)
This utility is used to clone a network policy rule or a priority policy rule into another network policy set or a priority policy set.

#### Synopsis
This tool lets you automate the process of policy rule creation. The CLI expects source and destination rule and policy set information.

#### Requirements
* Active CloudGenix Account
* Python >= 2.7 or >=3.6
* Python modules:
    * CloudGenix Python SDK >= 5.2.3b1 - <https://github.com/CloudGenix/sdk-python>
    * CloudGenix ID-Name Utility >= 2.0.1 - <https://github.com/ebob9/cloudgenix-idname>
* ProgressBar2

#### License
MIT

#### Installation:
 - **Github:** Download files to a local directory, manually run `getevents.py`. 

### Examples of usage:
Clone Network Policy Rule:
```
./clonepolicyrule.py -SP enterprise_nam -SR office365 -DP enterprise_eu -DR office365 -T NW
```
Clone Priority Policy Rule:
```
./clonepolicyrule.py -SP "Global QoS" -SR "VoIP and Meeting Apps" -DP "MediaQoS" -DR voip -T QOS
```

SJCMAC42VVH03Q:clonepolicyrule tanushreekamath$ ./clonepolicyrule.py -h
usage: clonepolicyrule.py [-h] [--controller CONTROLLER] [--email EMAIL]
                          [--pass PASS] [--type TYPE] [--srcpolicy SRCPOLICY]
                          [--srcrule SRCRULE] [--dstpolicy DSTPOLICY]
                          [--dstrule DSTRULE]

CloudGenix: Clone Policy Rule.

optional arguments:
  -h, --help            show this help message and exit

API:
  These options change how this program connects to the API.

  --controller CONTROLLER, -C CONTROLLER
                        Controller URI, ex. C-Prod:
                        https://api.elcapitan.cloudgenix.com

Login:
  These options allow skipping of interactive login

  --email EMAIL, -E EMAIL
                        Use this email as User Name instead of prompting
  --pass PASS, -P PASS  Use this Password instead of prompting

Policy Set & Rule Specific Information:
  Name policy set, rule and policy type that needs to be cloned

  --type TYPE, -T TYPE  Type of Policy Set. Allowed values: NW or QOS
  --srcpolicy SRCPOLICY, -SP SRCPOLICY
                        Source Policy Set Name
  --srcrule SRCRULE, -SR SRCRULE
                        Source Policy Rule. This is the rule that will be
                        cloned
  --dstpolicy DSTPOLICY, -DP DSTPOLICY
                        Destination Policy Set Name
  --dstrule DSTRULE, -DR DSTRULE
                        Destination Policy Rule. This new rule will be created
                        in the destination policy set
SJCMAC42VVH03Q:clonepolicyrule tanushreekamath$ 

#### Version
| Version | Build | Changes |
| ------- | ----- | ------- |
| **1.0.0** | **b1** | Initial Release. |


#### For more info
 * Get help and additional CloudGenix Documentation at <http://support.cloudgenix.com>
