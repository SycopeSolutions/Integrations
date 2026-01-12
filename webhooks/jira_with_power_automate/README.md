# Integrating Sycope with Jira Atlassian + Power Automate Using Webhooks

Below is a test example demonstrating how Sycope creates new Jira incidents as well as Jira comments. You can use the instructions below to configure the same setup. Incidents can be created automatically when an alert is triggered or manually via the context menu, as described further below.

Example view of the **IT Support** space showing multiple active incidents generated from **Sycope** alerts:

<img width="1909" height="884" alt="image" src="https://github.com/user-attachments/assets/aac1bc23-6f9c-4b47-b97e-5451b8788ced" />

**Example of Jira comments for a reoccurring issue:**  
This approach helps prevent the creation of duplicate incidents in Jira.

<img width="689" height="1047" alt="image" src="https://github.com/user-attachments/assets/5861a05b-6fef-4b80-9fc7-5130244f85a7" />


| ![IT Support Space View](https://github.com/user-attachments/assets/aac1bc23-6f9c-4b47-b97e-5451b8788ced) |


| ![Jira Comment Example](https://github.com/user-attachments/assets/5861a05b-6fef-4b80-9fc7-5130244f85a7) |


## Prerequirements

The following steps have been verified and are fully supported in the following environment:

- **Sycope** version 3.2 or later
- **Microsoft 365 Business Basic** or higher, with the **Power Automate Premium** add-on
