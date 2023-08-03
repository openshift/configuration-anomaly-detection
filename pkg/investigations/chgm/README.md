# ClusterHasGoneMissing Investigation

## Alert firing investigation

1. PagerDuty webhook receives CHGM alert from Dead Man's Snitch.
2. CAD Tekton pipeline is triggered via PagerDuty sending a webhook to Tekton EventListener.
3. Logs into AWS account of cluster and checks for stopped/terminated instances.
    - If unable to access AWS account, posts "cluster credentials are missing" limited support reason.
4. If stopped/terminated instances are found, pulls AWS CloudTrail events for those instances.
    - If no stopped/terminated instances are found, escalates to SRE for further investigation.
5. If the user of the event is:
    - Authorized (SRE or OSD managed), runs the network verifier and escalates the alert to SRE for futher investigation.
        - **Note:** Authorized users have prefix RH-SRE, osdManagedAdmin, or have the ManagedOpenShift-Installer-Role.
    - Not authorized (not SRE or OSD managed), posts the appropriate limited support reason and silences the alert.
6. Adds notes with investigation details to the PagerDuty alert.
   
## CHGM investigation overview

![CHGM investigation overview](./images/cad_chgm_investigation/chgm_investigation_dark.png#gh-dark-mode-only)
![CHGM investigation overview](./images/cad_chgm_investigation/chgm_investigation_light.png#gh-light-mode-only)