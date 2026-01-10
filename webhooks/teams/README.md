# Integrating Sycope with Microsoft Teams Using Webhooks

Below is a test example demonstrating how Sycope sends alert actions as new Microsoft Teams posts. You can use the instructions below to configure the same setup. Posts can be created automatically when an alert is triggered or manually via the context menu, as described further below.

<img width="1243" height="969" alt="image" src="https://github.com/user-attachments/assets/dfbb287a-447c-4d4d-beff-00fd10482fe7" />

The **View in Sycope** button can redirect users to the main **Alerts** view or to other dashboards. The integration can also support multiple buttons for different use cases.

<img width="1745" height="1050" alt="image" src="https://github.com/user-attachments/assets/7e5fc5bb-2ecd-4ae8-b449-f11044bd3173" />

Thanks to Power Automate features, you can use logical statements to dynamically change colors and icons based on the alert severity. In this example, yellow indicates **Medium** severity, while red represents **High** severity.

<img width="1025" height="988" alt="image" src="https://github.com/user-attachments/assets/7cd78539-c37b-43c9-a96f-e2d6df413ee1" />

## Step-by-Step Guide

All of the requirements listed below are included in all Office 365 plans. First, you need to have a Microsoft Teams **Team** defined. This can be done directly in Microsoft Teams by navigating to the **Chat** tab, scrolling down to **Teams and channels**, and selecting **See all your teams**.  

On the right-hand side, click **Create team** and provide the required **Team name** and **Channel name**. In our example, the **Team name** is **NOC Operators** and the **Channel name** is **Sycope Alerts**.

<img width="1010" height="749" alt="image" src="https://github.com/user-attachments/assets/8aed0195-a9c5-4787-ab94-21fea28ec541" />

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

Next, we need to provide a JSON example from Sycope so that Power Automate has a reference point for parsing it.

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

Next, select any active alert from the **Alerts** view and right-click its name.  

Choose: **Send externally → REST Client → YOUR_INTEGRATION_NAME**.  

A **Success** message should appear in the bottom-right corner.

<img width="1162" height="421" alt="image" src="https://github.com/user-attachments/assets/033da5fc-b2a9-46de-92ea-0ab23cbeb6e3" />

Now, return to **Microsoft Power Automate** and click the **Back** button.  

You should see a **Failed** status for the manual action from Sycope. This is expected, as the flow does not yet know how to process the alert.

<img width="1059" height="594" alt="image" src="https://github.com/user-attachments/assets/fed10753-91c0-4499-a2af-ab307df05e68" />

Click on the **Start date** to analyze our test.  

First, select **When a Teams webhook request is received**, then choose **Show raw output** under **OUTPUTS**

<img width="1231" height="563" alt="image" src="https://github.com/user-attachments/assets/294471c9-d00b-4542-88ad-70f3d14f6167" />

The output should look similar to the example below, but much longer.  

Please copy all the text into **Notepad** for reference.

<img width="571" height="175" alt="image" src="https://github.com/user-attachments/assets/dbdabb97-635e-43c7-9210-9520b60093a3" />

Now, you need to exit this test. Go back to our flow and click Edit.

Next, we need to modify the flow to handle Sycope alerts in **JSON** format, using the example we just sent.

Click the first **+** sign and select the **Parse JSON** action.

<img width="1049" height="250" alt="image" src="https://github.com/user-attachments/assets/469c4ce6-1a51-4b02-82a7-f406391cb77c" />

Select the **Parse JSON** action.  

Click **Use sample payload to generate schema** and paste the entire JSON alert from your Notepad.

<img width="1059" height="420" alt="image" src="https://github.com/user-attachments/assets/1384bb62-bcd9-4f26-8074-90344e9b15de" />

The final result should appear similar to the example below.  

You will notice that Power Automate has automatically generated the schema.

<img width="768" height="406" alt="image" src="https://github.com/user-attachments/assets/60532fea-5357-4be4-a8cc-10c4a7b79abc" />

For **Content**, click on the **lightning** symbol and select **Body**.

<img width="1007" height="306" alt="image" src="https://github.com/user-attachments/assets/bbcbbc7a-7b64-4acd-a0b8-e117f9bf8e2c" />

Next, move to the **Initialize variable (Body)** action. We will use it to create our **View in Sycope** button.

- Change the **Name** to `sycopeLink`  
- Set the **Type** to **String**
<img width="1071" height="469" alt="image" src="https://github.com/user-attachments/assets/c2fae530-8c43-4004-880f-0f871c4d606f" />

For **Value**, select **function**:
<img width="720" height="124" alt="image" src="https://github.com/user-attachments/assets/2158c2d8-7a78-47de-8476-3b53526c05c9" />

Use the following example:

concat(
    'https://YOUR_SYCOPE_IP_OR_DNS/panel/alerts?source=alerts&gq=%7B%22query%22:%7B%22source%22:%22alerts%22,%22nql%22:%22id%20%3D%20%5C%22',
    coalesce(body('Parse_JSON')?['id'],''),
    '%5C%22%22,%22advanced%22:false%7D,%22timerange%22:%7B%22from%22:%22startOfHour-30days%22,%22to%22:%22now%22,%22roundTo%22:%22hour%22%7D%7D'
)

It should appear as shown below:
<img width="995" height="248" alt="image" src="https://github.com/user-attachments/assets/49e26de8-cbf7-42ef-a31d-bc1dd5141551" />

You can remove any other unnecessary actions:

<img width="1009" height="374" alt="image" src="https://github.com/user-attachments/assets/408c10f4-4b81-4e27-b36c-548bac11fb48" />

We are now ready to add the most important action at the end of the flow: **Post card in a chat or channel**.

<img width="1002" height="341" alt="image" src="https://github.com/user-attachments/assets/f09c81df-8a8c-49d9-a096-5806eb31d812" />

Click on the new action and select the **Team** and **Channel** that you created at the beginning.

<img width="559" height="409" alt="image" src="https://github.com/user-attachments/assets/23a4b8c2-43b8-4129-9f90-c6d933d68a3a" />

For the **Adaptive Card**, we have prepared a dedicated JSON for you.  

Please download the file below and paste its content into the action:

https://github.com/SycopeSolutions/Integrations/blob/main/webhooks/teams/adaptivecard.json

This is how it should appear.  

You can see that all logical functions, such as if statements, are now represented by function icons, indicating they were recognized correctly. These functions enable mapping **Severity** to colors, along with a few other visual features.  

Once you click **Save**, Power Automate should display the message:  
*"Your flow is ready to go. We recommend you test it."*

<img width="991" height="608" alt="image" src="https://github.com/user-attachments/assets/898d09e0-34b2-4026-b466-800f04bc9fe2" />

Now for the best part!  

Return to Sycope, right-click any alert, and select **Send externally** to your Microsoft Teams integration.  

If everything is configured correctly, you should see a **Success** message in Power Automate:

<img width="1055" height="205" alt="image" src="https://github.com/user-attachments/assets/cfc4abe4-d95d-496a-9cf4-4853e282d4d6" />

You should now see a new alert posted in your Teams channel.

To have these posts executed automatically when an alert is triggered, navigate to **Configuration → Rules** and edit the desired rule.  

Under **Actions**, configure the following:

- **Type:** Third-party system (REST)
- **External system:** REST
- **Instance name:** `YOUR_NAME`
- **Threshold levels:** Select the levels that should trigger this action

The final result should appear as shown below:

<img width="930" height="509" alt="image" src="https://github.com/user-attachments/assets/cf0430b0-b75a-4a51-bd76-1593be89fe94" />

And that’s it! You should now see new Teams posts created each time this rule triggers an alert.
