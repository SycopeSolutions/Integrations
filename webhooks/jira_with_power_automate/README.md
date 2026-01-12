# Integrating Sycope with Jira Atlassian + Power Automate Using Webhooks

Below is a test example demonstrating how Sycope creates new Jira incidents as well as Jira comments. You can use the instructions below to configure the same setup. Incidents can be created automatically when an alert is triggered or manually via the context menu, as described further below.

Example view of the **IT Support** space showing multiple active incidents generated from **Sycope** alerts:

<img width="1909" height="884" alt="image" src="https://github.com/user-attachments/assets/aac1bc23-6f9c-4b47-b97e-5451b8788ced" />

**Example of Jira comments for a reoccurring issue:**  
This approach helps prevent the creation of duplicate incidents in Jira.

<img width="689" height="1047" alt="image" src="https://github.com/user-attachments/assets/5861a05b-6fef-4b80-9fc7-5130244f85a7" />

## Prerequirements

The following steps have been verified and are fully supported in the following environment:

- **Sycope** version 3.2 or later
- **Microsoft 365 Business Basic** or higher, with the **Power Automate Premium** add-on

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

To create new incidents in your **IT Support** project, you need to identify the `"key"` value from the output above.
It should look similar to the following:

        "id": "10034",
        "key": "IT",
        "name": "IT Support",

Next, create custom fields for `clientIp` and `serverIp` in Jira. These fields allow comparison of `alertName`, `clientIp`, and `serverIp` received from Sycope active alerts — the primary criteria for identifying potential duplicate incidents. When a duplicate is detected, the alert is added as a comment to the existing incident instead of creating a new one.  

Depending on your requirements, you may also consider adding additional fields to further refine duplicate detection.

To access the custom fields in Jira, navigate to:

**Settings → Work items** while on https://your_name.atlassian.net/jira/for-you

**OR** use the direct link: https://your_name.atlassian.net/jira/settings/issues/fields

<img width="513" height="414" alt="image" src="https://github.com/user-attachments/assets/a601da16-12dd-423b-933b-52038a5ce59a" />

Next, navigate to **Fields** and create the following custom fields using **Create new field** button:

1. **Client IP Field**
   - **Field type:** Short text (plain text only)  
   - **Name:** `clientIp`

2. **Server IP Field**
   - **Field type:** Short text (plain text only)  
   - **Name:** `serverIp`

You can verify the newly created fields by searching for `"ip"` in the Fields list.

<img width="803" height="450" alt="image" src="https://github.com/user-attachments/assets/c8c7f035-6510-4624-a3a5-0282832d38ec" />

