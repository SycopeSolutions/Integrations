# Integrating Sycope with Slack Using Webhooks

Modern SOC and NOC teams need real-time visibility into what’s happening in the network. While Sycope already provides deep observability and advanced alerting, it is often useful to push critical alerts directly into Slack, where teams collaborate every day.

Slack’s Incoming Webhooks make this integration simple: we can format messages, enrich them with emojis, and even add links to Sycope dashboards for instant investigation.

Creating a Slack Webhook:
1.	Navigate to Slack API – Your Apps (https://api.slack.com/apps)
2.	Select **Create New App → From scratch**, then provide an application name and choose the appropriate workspace.
3.	Once the application is created, open the **Incoming Webhooks** section and enable the feature by toggling the switch to On.
4.	Click **Add New Webhook** to Workspace, then select the channel where alerts should be posted.
5.	After the webhook is created, copy the generated URL. It will look similar to:
https://hooks.slack.com/services/T00000/zzzzzzzzzz

<img width="308" height="359" alt="image" src="https://github.com/user-attachments/assets/90e8a0e0-bb78-4924-b4cb-101e0b7920d9" />

## Sending a Basic Test Message

You can test the webhook using curl:
```
curl -X POST -H 'Content-type: application/json' \
--data '{"text":"Hello from Sycope 👋"}' \
https://hooks.slack.com/services/T00000/zzzzzzzzzz
```

The above test will be immediately visible on the chosen channel:

<img width="468" height="274" alt="image" src="https://github.com/user-attachments/assets/9259ca32-8f50-4154-a202-cdd84340b895" />

## Formatting Alerts with Blocks and Dividers

Slack messages can be structured with Block Kit, which supports headers, sections, fields, context, and buttons. This allows us to present Sycope alerts in a clean, human-friendly format.
To make alerts instantly recognizable, we recommend mapping severity levels to emoji icons:


| Sycope Thresholds Level  | Emoji | Example in Slack |
| ------------- | ------------- | ------------- |
| Critical  | `:red_circle:`  | 🔴 Critical |
| Major  | `:warning:`  | ⚠️ Major  |
| Minor  | `:large_blue_circle:`  | 🔵 Minor  |


The example below demonstrates an alert message that includes the Rule Type, Alert Name, Client IP, Server IP, Timestamp, and Severity, along with a “View in Sycope” button for direct access to the alert details within Sycope.

Within Slack, users can create threads on an alert message to collaborate, acknowledge the alert, and assign responsibility to a specific team member. This approach leverages the strengths of both Sycope and Slack, enhancing team efficiency and improving incident response workflows.
 
<img width="468" height="261" alt="image" src="https://github.com/user-attachments/assets/5360737f-b317-496e-be52-f4328346263e" />


## Creating a New External Action for Alerts

You can configure a new external action in Sycope, which may be triggered manually (by right-clicking an active alert) or automatically (by assigning it to a specific rule).
1.	Navigate to Settings → Integrations → External Destination in the Sycope web interface.
2.	Click **Add External Destination**.
3.	Select Type: **Rest Client**.
4.	Complete the configuration form using the example provided below (including **Custom Payload**).
5.	Click Save to finalize the setup.

<img width="468" height="468" alt="image" src="https://github.com/user-attachments/assets/abfbe360-5035-4af3-b34f-f965f2d4e978" />

A complete example of a custom payload in `payload_example.json` file is available in the slack folder. You can copy and paste it directly or adjust it to meet your specific requirements.
In the **Edit External Destination** form, you can select **Placeholders** to view all available dynamic values. These placeholders are automatically populated with data when the action is executed.

In addition to the built-in placeholders, users also have access to custom **result** values from triggered alerts. For example, to reference the **serverIp** value from an active alert, use the following placeholder: `[(${result.serverIp})]`
https://github.com/SycopeSolutions/Integrations/blob/main/webhooks/slack/payload_example.json

Users can reference any available value through the **result** object. The corresponding field names can be identified in the **Alerts** dashboards by enabling the **“Show raw field names”** option.

<img width="468" height="276" alt="image" src="https://github.com/user-attachments/assets/d84205b1-2513-4d85-a32d-beb8ed6a6f84" />

To view the full details of an active alert, users can click **“View in Sycope”**, which redirects them to the **Alerts** dashboard with the corresponding AlertId automatically applied as a filter.
Please note that the button can be configured to open any dashboard or view, depending on your requirements.

<img width="1920" height="1175" alt="1" src="https://github.com/user-attachments/assets/e39718fa-2a8c-437b-ba34-468c5ae82bac" />

## Best Practices

We recommend below best practices to achieve the best workflow in the team.
- Use dedicated channels (e.g. #security-alerts, #network-ops) to avoid noise.
- Choose the right fields for the specific team to make it easy for engineers to triage alerts directly inside Slack
- Group related fields into columns using fields blocks.
- Always include a link back to Sycope for quick root-cause analysis.
- Use emojis for severity and system type to increase readability.

## Conclusion

By integrating Sycope with Slack via webhooks, you bring network observability into your collaboration hub. Alerts are delivered in real time, formatted with context, and linked back to Sycope dashboards for investigation.

This setup enhances responsiveness, improves incident handling, and helps teams act on behavioral threat detections, rogue device alerts, and anomaly detection without delay.
