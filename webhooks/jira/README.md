# Integrating Sycope with Jira Atlassian Using Webhooks

Below is a test example demonstrating how Sycope creates new Jira incidents. You can use the instructions below to configure the same setup. Incidents can be created automatically when an alert is triggered or manually via the context menu, as described further below.

<img width="1909" height="762" alt="image" src="https://github.com/user-attachments/assets/ad3d4da7-cbb8-44a5-953b-f97a6fbfac96" />

## Prerequirements

The following steps have been verified and are fully supported in the following environment:

- **Sycope** version 3.2 or later
- **Atlassian Jira Free** (supports up to 10 users or 3 agents) or higher

## Step-by-Step Guide

First, please create a new IT Service Management Space, or another Space with a similar configuration.
Available Spaces can be accessed here: https://YOUR_NAME.atlassian.net/jira/for-you

<img width="1448" height="596" alt="image" src="https://github.com/user-attachments/assets/02b9329e-d156-4b68-ab6d-e40e280b750c" />

The new Space should be visible in your Jira Service Desk projects. In our example, we used “IT Support” and “HelpDesk”.
Defined Spaces can be accessed here: https://YOUR_NAME.atlassian.net/jira/projects

<img width="1507" height="600" alt="image" src="https://github.com/user-attachments/assets/b6e31691-d71b-4ba1-997e-40bfb4c2939f" />

Next, navigate to your Atlassian profile, go to **Security**, and create a new API token.
API tokens can be managed and created here: [https://id.atlassian.com/manage-profile/security/api-tokens](https://id.atlassian.com/manage-profile/security/api-tokens)

<img width="1038" height="365" alt="image" src="https://github.com/user-attachments/assets/1505eca6-ebbd-473d-903a-d24dc07bb458" />

Now you can communicate with the Jira API using your email address as the **username** and the API token as the **password**.
Use **Basic Auth** for authentication.

Send an HTTPS `GET` request to your projects URL, which should look like this:

https://YOUR_NAME.atlassian.net/rest/api/3/project

You can use below **curl** command, **Postman** or any other HTTP client to send the request. 

**Important:** Use **Basic Authentication** with:
- **Username:** your Jira email address
- **Password:** your Jira API token

        curl -X GET \
        https://YOUR_NAME.atlassian.net/rest/api/3/project \
        -H "Accept: application/json" \
        -u "EMAIL:API_TOKEN"

To create new incidents in your **IT Support** project, you need to identify the `"key"` value from the output above.
It should look similar to the following:

        "id": "10034", <<<<<--------
        "key": "IT",
        "name": "IT Support",

You now have everything needed to create a new alert action in **Sycope** and start creating Jira incidents automatically.

## Creating a New Jira Integration in Sycope

First, go to **Settings → General → Integrations → External Destinations** and click **Add External Destination**.

Please define the following values:

- **Name:** As per your requirements  
- **URL Protocol:** HTTPS  
- **URL Host:** `YOUR_NAME.atlassian.net`  
- **URL Port:** 443  
- **Method:** POST  

- **Path:** `/rest/api/3/issue`  

- **Authentication:** Basic  
  - **Username:** `YOUR_EMAIL`  
  - **Password:** `YOUR_TOKEN`  

- **Custom Payload:** Enabled  

For the **Custom Payload** body, use the ready-to-go example from our repository:  
[https://github.com/SycopeSolutions/Integrations/blob/main/webhooks/jira/payload_example.json](https://github.com/SycopeSolutions/Integrations/blob/main/webhooks/jira/payload_example.json)


You need to modify the following values in the payload:

- `"key": "IT"` → replace with the specific key of your Jira project  
- `https://SYCOPE_IP` → replace with the IP address or DNS record of your Sycope installation

The final result should appear as shown below:
<img width="714" height="812" alt="image" src="https://github.com/user-attachments/assets/9a669ab7-5269-4638-b73d-9d53466002c1" />

You can start using your new integration immediately via the **Context Menu**.  
While viewing **Alerts**, right-click an active alert and select your action from:

**Send externally → REST Client** list

<img width="943" height="425" alt="image" src="https://github.com/user-attachments/assets/2e2f91b0-d92c-4121-a5a9-74dd79816dad" />

This action will create a new incident, which should appear as shown below:
<img width="1904" height="750" alt="image" src="https://github.com/user-attachments/assets/183c0574-5cbc-4c59-a76b-66391a0d6c21" />

To have these actions executed automatically when an alert is triggered, navigate to **Configuration → Rules** and edit the desired rule.  

Under **Actions**, configure the following:

- **Type:** Third-party system (REST)  
- **External system:** REST  
- **Instance name:** `YOUR_NAME`  
- **Threshold levels:** Select the levels that should trigger this action  

The final result should appear as shown below:

<img width="1899" height="1029" alt="image" src="https://github.com/user-attachments/assets/8645de39-e5e7-4815-b3a6-6824c391dcbc" />

And that’s it! You should now see new Jira incidents created each time this rule triggers an alert.
