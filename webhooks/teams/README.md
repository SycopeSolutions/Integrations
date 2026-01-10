# Integrating Sycope with Microsoft Teams Using Webhooks

Below is a test example demonstrating how Sycope sends alert actions as new Microsoft Teams posts. You can use the instructions below to configure the same setup. Posts can be created automatically when an alert is triggered or manually via the context menu, as described further below.

<img width="1243" height="969" alt="image" src="https://github.com/user-attachments/assets/dfbb287a-447c-4d4d-beff-00fd10482fe7" />

The **View in Sycope** button can redirect users to the main **Alerts** view or to other dashboards. The integration can also support multiple buttons for different use cases.

<img width="1745" height="1050" alt="image" src="https://github.com/user-attachments/assets/7e5fc5bb-2ecd-4ae8-b449-f11044bd3173" />

Thanks to Power Automate features, you can use logical statements to dynamically change colors and icons based on the alert severity. In this example, yellow indicates **Medium** severity, while red represents **High** severity.

<img width="1025" height="988" alt="image" src="https://github.com/user-attachments/assets/7cd78539-c37b-43c9-a96f-e2d6df413ee1" />

## Prerequirements

All of the requirements listed below are included in all Office 365 plans. First, you need to have a Microsoft Teams **Team** defined. This can be done directly in Microsoft Teams by navigating to the **Chat** tab, scrolling down to **Teams and channels**, and selecting **See all your teams**.  

On the right-hand side, click **Create team** and provide the required **Team name** and **Channel name**. In our example, the **Team name** is **NOC Operators** and the **Channel name** is **Sycope Alerts**.

<img width="1069" height="715" alt="image" src="https://github.com/user-attachments/assets/3d488c9e-b2d1-459c-8ce1-e7a415839923" />

Next, you need to create a new webhook in **Microsoft Power Automate**. This can be done at:  
[https://make.powerautomate.com/](https://make.powerautomate.com/)

In the **My flows** tab, click **New flow** and select **Template**.  
From the available templates, search for the keyword **webhook** and choose **Send webhook alerts to a channel**.

<img width="1152" height="518" alt="image" src="https://github.com/user-attachments/assets/74fa4393-b354-4332-9299-d591f339acbe" />

You will be prompted to choose which account should be used to connect **Power Automate** with **Microsoft Teams** in your organization. You can use your own email address or select a dedicated **service account** with Office 365 enabled.  

For this example, a personal account is used. Once completed, it should appear as shown below:

<img width="1888" height="593" alt="image" src="https://github.com/user-attachments/assets/1b7d9472-e987-4566-b188-081c8634104e" />

Next, click **Edit** to prepare the flow to receive alerts from Sycope.  

Select the **When a Teams webhook request is received** block and copy the webhook URL. It should look similar to the following:

https://xxxxxxxxxxx.dc.environment.api.powerplatform.com:443/powerautomate/automations/direct/workflows/xxxxxxxxxx/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=xxxxxxx

From this screen, you can also restrict which accounts are allowed to trigger the webhook.  

For testing purposes, we will leave it set to **Anyone**.

<img width="1079" height="476" alt="image" src="https://github.com/user-attachments/assets/0fd962ba-bb2b-4ce4-82de-3ee80aeb2a95" />

Next, we need to modify the flow to handle Sycope alerts in **JSON** format.  

Click the first **+** sign and select the **Parse JSON** action.

<img width="1049" height="250" alt="image" src="https://github.com/user-attachments/assets/469c4ce6-1a51-4b02-82a7-f406391cb77c" />

Other actions from the template are not required, so please remove them.

<img width="1051" height="358" alt="image" src="https://github.com/user-attachments/assets/40a7e568-e52b-444a-8214-ce571dfcbefa" />

Next, we need to provide a JSON example from Sycope for the **Parse JSON** action, so that Power Automate has a reference point.  

Log in to Sycope and create a new integration by navigating to:  

**Settings → General → Integrations → External Destinations**  

Then click **Add External Destination**.

It is necessary to split the Webhook URL into individual query parameters.  

You can do this automatically using **Postman** or another tool, or manually using the example below.

Our test URL is https://xxxxxxxxxxx.dc.environment.api.powerplatform.com:443/powerautomate/automations/direct/workflows/xxxxxxxxxx/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=xxxxxxx

Main parameters:
- **Name:** As per your requirements
- **URL Protocol:** HTTPS
- **URL Host:** `xxxxxxxxxxx.dc.environment.api.powerplatform.com`
- **URL Port:** 443
- **Method:** POST
- **Path:** /powerautomate/automations/direct/workflows/xxxxxxxxxx/triggers/manual/paths/invoke

Query params:
- **api-version:** 1
- **sp:** /triggers/manual/run
- **sv:** 1.0
- **sig:** xxxxxxx

The final result should appear as shown below:
<img width="713" height="932" alt="image" src="https://github.com/user-attachments/assets/082e074b-0830-474e-a074-2d75ea185963" />

There is no need to edit other tabs and your new Integration can now be saved.
