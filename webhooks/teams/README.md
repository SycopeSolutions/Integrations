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



