# Integrating Sycope with Jira Atlassian Using Webhooks

Below is a test example demonstrating how Sycope creates new Jira incidents. You can use the instructions below to configure the same setup. Incidents can be created automatically when an alert is triggered or manually via the context menu, as described further below.

<img width="1909" height="762" alt="image" src="https://github.com/user-attachments/assets/ad3d4da7-cbb8-44a5-953b-f97a6fbfac96" />

## Prerequirements

All of the requirements listed below are included in the Jira Free tier. First, please create a new IT Service Management space, or another space with a similar configuration.

<img width="1448" height="596" alt="image" src="https://github.com/user-attachments/assets/02b9329e-d156-4b68-ab6d-e40e280b750c" />

The new space should be visible in your Jira Service Desk projects. In our example, we used “IT Support” and “HelpDesk”.

<img width="1507" height="600" alt="image" src="https://github.com/user-attachments/assets/b6e31691-d71b-4ba1-997e-40bfb4c2939f" />

Next, navigate to your Atlassian profile, go to **Security**, and create a new API token.

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

You now have everything needed to create a new alert action in **Sycope** and start creating Jira incidents automatically.

## Sycope

