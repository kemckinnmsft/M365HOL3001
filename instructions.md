# Implementing Microsoft 365 Security Technologies

## INSTRUCTOR LED LAB - M365HOL3001

### Introduction

This lab is designed to be used as a supplement to Instructor Led Training and has several sections that you will go through over the next few days. Please click the lab below that corresponds to the technology your are working with.  You will have access to this environment for 6 months following the event.

## [Lab Environment Configuration](#lab-environment-configuration)

## [Lab 1: Microsoft 365 Cloud App Security](#microsoft-365-cloud-app-security)

## [Lab 2: Azure Information Protection](#azure-information-protection)

## [Lab 3: Windows Defender Advanced Threat Protection](#windows-defender-advanced-threat-protection)

## [Lab 4: Azure Advanced Threat Protection](#azure-advanced-threat-protection)

## [Lab 5: Office 365 Advanced Threat Protection](#office-365-advanced-threat-protection)

## [Lab 6: Azure Security Center](#azure-security-center)

## [Lab 7: Azure Active Directory](#azure-active-directory)

> [!ALERT] When stopping each section, please ensure that you SAVE the session inbetween labs rather than END the lab.  If you end the lab, all VM configuration will be reset to initial state and will hinder the experience during future labs.  We have designed this lab to be a good representation of the interoperability between Microsoft 365 Security Technologies so several of the labs will feed information into future labs.


===
# Tips and Tricks
[🔙](#introduction)

There are a few extras throughout this lab that are designed to make your lab experience a smooth and simple process.  Below are some icons you should watch out for that will save you time during each task.

## Interactive Elements

- Each task contains a series of steps required for successful completion of the lab.  To track your progress throughout the lab, check the box to the left of the numbered series.  

	![6mfi1ekm.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/6mfi1ekm.jpg)
- After you check each box, you will see your lab progress at the bottom of the instruction pane.

	![0ggu265u.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/0ggu265u.jpg)
- When you see an instruction for switching computers, click on the **blue link** in the text to have that VM loaded automatically.

	![12i85vgl.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/12i85vgl.jpg)
- Throughout the lab, you will see green text with a letter **T** in a square to the left.  This indicates that you can **click on the text** and it will **type it for you** in the VM.  **This will save you lots of time**.

	![cnyu1tdi.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/cnyu1tdi.jpg)
- You will also see Blue Click here links with a lightening bolt that will launch applications for you.  Alternate instructions are typically also provided below these links.

	![m2zvmfhk.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/m2zvmfhk.jpg)
- The last interactive element you will see throughout the lab is the **Open Screenshot** text below many steps.  To reduce clutter, most screenshots have been configured to launch in a popup window.  The only ones left visible are ones that could cause issues if they are missed or if there are multiple elements that are easier to understand with visual representation.

	![n4cqn070.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/n4cqn070.jpg)

## Additional Information

There are also Knowledge Items, Notes, and Hints throughout the lab.

- Knowledge Items are used to provide additional information about a topic related to the task or step.  These are often collapsed to reduce the amount of space they use, but it is recommended that you review these items if you want more information on the subject.

	![8g9nif1j.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/8g9nif1j.jpg)
- Notes are steps that do not require action or modification of any elements.  This includes general observations and reviewing the results of previous steps.

	![kxrbzsr2.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/kxrbzsr2.jpg)
- Hints are recommendations or observations that help with the completion of a step.

	![w11x99oo.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/w11x99oo.jpg)

[🔙](#introduction)
===
# Lab Environment Configuration
[🔙](#introduction)
- Configure Azure AD Connect on Scanner01
- Run scripts on VictimPC
- Configure Azure ATP

	>![52a7iwuj.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/52a7iwuj.jpg)
===
# Microsoft 365 Cloud App Security
[🔙](#introduction)

This lab will guide you through some of the Microsoft Cloud App Security
(MCAS) capabilities.

We expect you to already have experience with MCAS deployment and
configuration. In the different sections, you will be asked to fulfill
some tasks for which you will receive the requirements but not a step by
step guide to accomplish this task. A lab answer key document can be
provided to those needing it.

- [Cloud Discovery](#cloud-discovery)
- [Threat Detection](#threat-detection)
- [Conditional Access App Control](#conditional-access-app-control)
- [Management](#management)

===
# Cloud Discovery
[🔙](#microsoft-365-cloud-app-security)

### Estimated time to complete
30 min

Continuous reports in Cloud Discovery analyze all logs that are
forwarded from your network using Cloud App Security. They provide
improved visibility over all data, and automatically identify anomalous
use using either the Machine Learning anomaly detection engine or by
using custom policies that you define.
To use this capability, you will perform in this lab the configuration
and troubleshooting of the Cloud Discovery feature.
===
## Configure and test continuous reports

1. []  By following the procedure provided in the documentation
    (<https://docs.microsoft.com/en-us/cloud-app-security/discovery-docker-ubuntu>)
    , deploy a new log collector on **LinuxVM**. The
    receiver type must be **FTP** and the data source must be **SQUID**
    (Common).

    You are also asked to anonymize the usernames.
    Use Putty on **AdminPC** to open a session to
    **LinuxVM** to perform the configuration.

1. []  To validate your configuration, upload a SQUID sample log to your log collector with the **Win SCP** client installed on
    **AdminPC**.
    Sample logs are downloadable in MCAS when creating new sources.
	
	![g5txg1zn.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/g5txg1zn.jpg)

	![pdp28e19.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/pdp28e19.jpg)
  
1. []    In WinSCP, you have to create a new connection using the credentials
    provided during the log collector creation, its IP address and
    port 21. Then, you upload the logs into the folder named as the data
    source you created in MCAS.
	
	![bgyxrnmh.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/bgyxrnmh.jpg)

1. []  After uploading your logs, verify the processing status in MCAS
    using the Governance log. Verify also the "last data received"
    status of your data source in the "Automatic log upload" status.

1. [] After validating that your logs have been successfully uploaded and
    processed by MCAS, you will not see directly the analysis of your
    data. Why? (hint: verify the "Set up Cloud Discovery" documentation
    page).
===
## Integrate MCAS with Windows Defender Advanced Threat Protection

Microsoft Cloud App Security leverages the traffic information collected
by Windows Defender ATP about the cloud apps and services being accessed
from IT-managed Windows 10 machines. This enables you to run Cloud
Discovery on any machine in the corporate network, using public wifi,
while roaming and over remote access. It also enables machine-based
investigation.

To complete this lab, you have to onboard your Windows 10 devices as
explained in the documentation
(<https://docs.microsoft.com/en-us/cloud-app-security/wdatp-integration>).
Not all Windows 10 devices will provide your Cloud Discovery data. Why?
What are the prerequisites to use this native integration?

Once the integration is complete, you will have a new continuous report
in the Discovery reports.

![3ezcsz80.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/3ezcsz80.jpg)
===
## How to troubleshoot the Docker log collector

In this task, you will review possible troubleshooting steps to identify
issues in automatic logs upload from the log collector.

There are several things to test at different locations: in the log
collector, in MCAS, at the network level.

### Verify the log collector (container) status

On @lab.VirtualMachine(AdminPC).SelectLink, open a session on Putty to **LinuxVM** and use on the following commands:

*sudo -i*

 

*docker stats*

This command will show you the status of the log collector instance:

![CONTAINER ID 2d7cadgfS4a1 13.14\* CPU 1.22\* MEM USAGE / LIMIT 187
.1MiB / 1.39GiB NET I/o 10.gMB / 3 .23MB](vl5158cy.jpg)

 

*docker logs \--details name\_of\_your\_log\_collector *

This command will show you the logs from the log collector to verify if
it encountered errors when initiating:



![rootaubuntu-srt: \'hame,\'seb 5 \--dzt.ei15 Setting ftp configuration
Enter again: Setting syslog Reading configuration.. . Installing
collector successfully! zenzitive Starting 2018-06-28 2018-06-28
2018-06-28 2010-06-28 2018-06-28 08 2018-06-28 2018-06-28 seo 2018-06-28
53B 2018-06-28 €67 2018-06-28 2018-06-28 667 08:28: is, CRIT WARN I NEO
CR IT I NEO 1 NEO INFO I NEO INSO I NEO INFO I NEO INFO as uzez in file)
during parsing RBC interface \' supervisor • initialized http without
HTTP checking Started With pid 1059 spawned: spawned : success : • with
1062 •rsyslog• with pid 1063 with pid 2064 • Columbus\' with 1065
rsyslog RUNNING stace, ftpd entered RUNNING state, pza RUNNING scat\* ,
Stayed up for](4bfomeag.jpg)

 

To go further in the troubleshooting, you can connect to the log
collector container to investigates the different logs, using the
following command:\
*docker exec -it name\_of\_log\_collector bash*

You can then explore the container filesystem and inspect the
**/var/adallom** directory. This directory is where you will investigate
issues with the syslog or ftp logs being sent to the collector\
![ovjlyn26.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/ovjlyn26.jpg)

-   **/adallom/ftp/discovery**: this folder contains the data source
    folders where you send the log files for automated upload. This is
    also the default folder when logging into the collector with FTP
    credentials.

-   **/adallom/syslog/discovery**: if you setup the log collector to
    receive syslog messages, this is where the flat file of aggregated
    messages will reside until it is uploaded.

-   **/adallom/discoverylogsbackup**: this folder contains the last file
    that was sent to MCAS. This is useful for looking at the raw log in
    case there are parsing issues.

To validate that logs are correctly received from the network appliance,
you can also verify the **/var/log/pure-ftpd** directory and check the
transfer log:
![erx39v7i.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/erx39v7i.jpg)

Now, move to the **/var/log/adallom** directory.
![0h029uih.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/0h029uih.jpg)

-   **/var/log/adallom/columbus**: this folder is where you will find
    log files useful for troubleshooting issues with the collector
    sending files. In the log-archive folder you can copy previous logs
    compressed as .tar.gz files off the collector to send to support.

-   **/var/log/adallom/columbusInstaller**: this is where you will
    investigate issues with the collector itself. You will find here
    logs related to the configuration and bootstrapping of the
    collector. For example, trace.log will show you the bootstrapping
    process:
    ![ks4ttuuq.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/ks4ttuuq.jpg)

 

 

### Verify the connectivity between the log collector and MCAS

An easy way to test this is to download a sample of your appliance logs
from MCAS and use WinSCP to connect to the log collector to upload that
log and see if it gets uploaded to MCAS.

 

Upload the logs in the folder named by your source:

![bqhxmpns.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/bqhxmpns.jpg)

 

Then, check in MCAS the status:

![21pseval.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/21pseval.jpg)

 

![mt0o095m.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/mt0o095m.jpg)

 

If the log stays in the source folder, then you know you probably have a
connection issue between the log collector and MCAS.

Another way to validate the connection is to log into the container like
in the previous task and then run *netstat -a* to check if we see
connections to MCAS:![rxvauw6e.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/rxvauw6e.jpg)
===
# Threat Detection
[🔙](#microsoft-365-cloud-app-security)

### Estimated time to complete
20 min

Cloud App Security provides several [threats detection
policies](https://docs.microsoft.com/en-us/cloud-app-security/anomaly-detection-policy)
using machine learning and **user behavior analytics** to detect
suspicious activities across your different applications. After an
initial learning period, Cloud App Security will start alerting you when
suspicious actions like activity from anonymous IP addresses, infrequent
country, suspicious IP addresses, impossible travel, ransomware
activity, suspicious inbox forwarding configuration or unusual file
download are detected.

In addition to those policies, you can create your own policies, like
the ones on the next page, that you must create for this lab.
===
## Policies

### Exchange Online -- monitor mail forwarding configuration

This policy allows you to monitor admin and users mail forwarding
configuration. This policy is covering extra scenarios than the built-in
one.

**Activities to monitor:**

  |App               |Activity category              |Activity
  |----------------- |------------------------------ |---------------
  |Exchange Online   |Create forwarding inbox rule   |New-InboxRule
  |Exchange Online   |Edit mailbox forwarding        |Set-Mailbox
  |Exchange Online   |Edit forwarding inbox rule     |Set-InboxRule

As creating this kind of rules is part of the daily operations in a
company, we could recommend scoping the monitoring to **sensitive
groups** of users to monitor but this is not required for this lab.

![deg5ncg3.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/deg5ncg3.jpg)

### Exchange Online - add user to Exchange administrator role

This policy monitors when a user is added to an Exchange management role
group.

Although this action is usually legit, providing visibility on it is
usually required by security teams.

**Activities to monitor:**
  |App               |Activity category             |Activity
  |----------------- |---- 							|---------------------
  |Exchange Online   |N/A   						|Add-RoleGroupMember

Optionally, you could add as a condition "if IP address category is not
in Corporate".

![ao3du4ms.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/ao3du4ms.jpg)

### Exchange Online - Add management role assignment

This rule monitors possible management role assignments to a management
group.

For example, when someone is adding impersonation capabilities to a
group used to migrate mailboxes to Office 365.

Details about Exchange permissions and roles can be found [at this
address](https://docs.microsoft.com/en-us/exchange/permissions-exo/permissions-exo).

**Activities to monitor:**
  |App               |Activity category                   |Activity
  |----------------- |----------------------------------- |---------------------
  |Exchange Online   |Add impersonation role assignment   |New-ManagementRoleAssignment

![rilw99v2.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/rilw99v2.jpg)

### Exchange Online - New delegated access to sensitive mailbox

This policy monitors when a delegate is added to sensitive mailboxes,
like your CEO or HR team mailboxes or sensitive shared mailboxes.

We monitor two kinds of delegation: at the mailbox level, when an admin
performs the action, and at the client level, when delegation for
folders are added.

**Note**: Exchange logs can take some time before being available,
leading to some delay before the detection.

**Activities to monitor:**

We recommend scoping this policy to specific users only, to avoid too
many alerts, but this is not required for this lab.

  |App               |Activity category                   |Activity
  |----------------- |----------------------------------- |---------------------
  |Exchange Online   |Add mailbox folder permission   	  |Add-MailboxFolderPermission
  |Exchange Online   |Add permission to mailbox       	  |Add-MailboxPermission

![6kcy2xki.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/6kcy2xki.jpg)

### OneDrive -- Ownership granted to another user

This policy helps you to detect when someone is granted full access to
somebody OneDrive for Business site.

**Activities to monitor:**

  |App               |Activity category                   |Activity
  |----------------- |----------------------------------- |---------------------
  |OneDrive   		 |Add site collection administrator   |SiteCollectionAdminAdded

![rb4fqb83.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/rb4fqb83.jpg)

### 3rd party apps delegations

This policy helps you to detect new external apps for which users are
granting access to the select app (Office 365, G Suite, ...).

Detecting those delegations will help in the case of cloud ransomware,
or possible data exfiltration.

**Activities to monitor:**

We will monitor when an uncommon app is granted medium or high
permission level:

![mszki5q9.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/mszki5q9.jpg)

### Investigation in MCAS

Now that we have created those policies, we are going to investigate on
the alerts.

As your environments auditing might not be configured yet and will take
up to 24h before being enabled, those investigations will be performed
in the environment provided by your instructor.

Review the alerts in the environment and investigate to identify the
users and the malicious activities performed.

===
# Conditional Access App Control
[🔙](#microsoft-365-cloud-app-security)

### Estimated time to complete
40 min

Please go through all the steps exactly as described to avoid
complications.

### Configure Salesforce

1.  Create a Salesforce developer account

    1.  Go to <https://developer.salesforce.com/signup>

    2.  **Important:** Use your admin user as the Email
        and Username

        i.  E.g., <@lab.CloudCredential(81).Username>

    3.  Fill in the rest of details, click Sign me up, accept the
        verification email, and choose a new password.

2.  Configure Salesforce in Azure AD

    1.  In Salesforce, go to **Setup**, search for **My Domain** and
        register a new domain, e.g., ems123456-dev-ed.salesforce.com
        ![f7idpipy.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/f7idpipy.jpg)

    5.  Save **full Salesforce domain name**, including https:// for the
        next step, e.g., <https://ems123456-dev-ed.salesforce.com>

    6.  Go to portal.azure.com logging in with the same admin (e.g.,
        <@lab.CloudCredential(81).Username>) and go to **Azure Active
        Directory**, click on **Enterprise applications**, choose **+
        New application**, select All, choose **Salesforce**, call it
        **SalesforceCAS**, and click on **Add**

    7.  Go back to **Enterprise applications**, choose **All
        applications**, and click on **SalesforceCAS**, click on
        **Single sign-on**, and choose **SAML-based Sign-on** under
        **Single Sign-on Mode**

    8.  For both **Sign on URL** and **Identifier** set the full
        Salesforce domain name, e.g.,
        <https://ems123456-dev-ed.salesforce.com>

    9.  Under SAML Signing Certificate, make sure that there is a
        certificate present and that the **STATUS** is **Active**

        1. If there is no certificate, click on the **Create new
            certificate** link

        1. If the **STATUS** is **New**, select the **Make new
            certificate active** checkbox. When you click on **Save**,
            you will get a **Rollover certificate** confirmation. Once
            certificate rollover is approved, the certificate STATUS
            will become **Active**.

    10. Click on **Save**

    11. Click on **Configure Salesforce** which will open a new blade

    12. Scroll down to the **Quick Reference** section

        1. **Download the Azure AD Signing Certificate**

        1.  Copy all the other fields in the Quick Reference section for
            the next step in Salesforce

    13. Go back to Salesforce, under **Setup** go to **Single Sign-On
        Settings**
        ![ao0yrpx8.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/ao0yrpx8.jpg)

    14. Click on **Edit**, Select **SAML Enabled**, and click on
        **Save**

    15. In the same **Single Sign-On Settings** page, click on **New**

    16. Fill in the following fields:

        1. **Name**: write "Azure AD"

        1. **Issuer**: Copy and paste the **Azure AD SAML Entity ID**
            from the Azure AD **Quick Reference** section

        1. **Entity ID**: The full Salesforce domain, e.g.,
            <https://ems123456-dev-ed.salesforce.com>

        1. **Identity Provider Certificate**: upload the certificate
            you've downloaded from Azure AD (**Download Azure AD Signing
            Certificate**)

        1.  **Identity Provider Login URL**: Copy and paste the **Azure
            AD Single Sign-On Service URL** from the Azure AD **Quick
            Reference** section

        1. **Custom Logout URL**: Copy and paste the **Azure AD Sign
            Out URL** from the Azure AD **Quick Reference** section

    17. Click **Save**

    18. Go back to **My Domain** in Salesforce

    19. Under **Authentication Configuration** click Edit, (click
        **Open** if needed), and:

        1. Uncheck the **Login Page** checkbox

        1. Check the **Azure AD** checkbox

        1. Click on **Save**

    20. Go back to the Azure AD portal, within the **SalesforceCAS**
        app, choose **Users and groups**
        
		![kscnoob4.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/kscnoob4.jpg)

    21. Click on **+ Add user**, choose the admin as the user (e.g.,
        <admin@ems123456.onmicrosoft.com>), choose **System
        Administrator** as the Role, and click on **Assign**

    22. Test the setup by going to <https://myapps.microsoft.com>,
        logging in with the admin user (e.g.,
        <admin@ems123456.onmicrosoft.com>) and clicking on the
        **SalesforceCAS**, verifying that this will result in a
        successful login to Salesforce.

3.  Deploy the proxy for Salesforce

    1. In Azure Active Directory, under **Security**, click
        on **Conditional access**.
        ![b62lha77.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/b62lha77.jpg)

    24. Click on **New policy** and create a new policy:

        1. Name the policy: Test Cloud App Security proxy

        1. Choose the admin as the user (e.g.,
            <admin@ems123456.onmicrosoft.com>)

        1. Choose SalesforceCAS as the app

        1.  Under **Session** you select **Use proxy enforced
            restrictions**.

        1. Set **Enable policy** to be **On**

        1. Click on **Create**

        1. It should look like this:
            ![qti7w9u6.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/qti7w9u6.jpg)

    25. After the policy was created successfully, open a new browser,
        [make sure you are logged out]{.underline}, and log in to
        SalesforceCAS with the admin user

        1. You can go to <https://myapps.microsoft.com> and click on
            the SalesforceCAS tile

        1.  Make sure you've successfully logged on to Salesforce

    26. Go to the Cloud App Security portal, and under the settings cog
        choose **Conditional Access App Control
        ![dfmwyegm.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/dfmwyegm.jpg)

    27. You should see a message letting you know that new Azure AD apps
        were discovered. Click on the **View new apps** link.
        ![qz9mx11x.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/qz9mx11x.jpg)

        1. If the message does not appear, go back to step c. (After
            the policy was created...) this time, close the browser and
            open a new browser in Incognito mode.

    28. In the dialog that opens, you should see Salesforce. Click on
        the + sign, and then click **Add**.
        ![iy3f8gro.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/iy3f8gro.jpg)

### Configure device authentication

1.  Go to the settings cog and choose **Device identification**.

2.  Upload the CASTestCA.crt certificate from the Client Certificate
     folder within the **E:\Demofiles.zip** file you've received as the
     certificate authority root certificate

	![rlkp1xvp.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/rlkp1xvp.jpg)
### Create a session policy

1.  In the Cloud App Security portal, select **Control** followed
     by **Policies**.

2.  In the **Policies** page, click **Create policy** and
     select **Session policy**.
     ![6lh61nkl.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/6lh61nkl.jpg)

3.  In the **Session policy** window, assign a name for your policy,
     such as *Block download of sensitive documents to unmanaged
     devices.*
     ![a6i9js1x.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/a6i9js1x.jpg)

4.  In the **Session control type** field Select **Control file download
     (with DLP)** 
	 ![j9pxy1lm.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/j9pxy1lm.jpg)

5.  Under **Activity source** in the **Activities matching all of the
     following** section, select the following activity filters to
     apply to the policy:

    1. **Device tags** does not equal **Valid client certificate**

    1. **App** equals **Salesforce**
    ![6wwuqlcz.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/6wwuqlcz.jpg)

6.  Check the **Enabled** checkbox near **Content inspection**

7.  Check the **Include files that match a preset expression** radio
     button

8.  In the dropdown menu just below the radio button, scroll all the way
     to the end to choose **US: PII: Social security number**

9.  Check the **Don't require relevant context** checkbox, just below
     the dropdown
     menu
	 ![10uz9qp1.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/10uz9qp1.jpg)

10. Under **Actions**, select **Block**

11. Check the **Customize block message** checkbox, and add a custom
     message in the textbox that has opened, e.g.: "This file is
     sensitive"
    ![dzdsku3w.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/dzdsku3w.jpg)

12. Click on **Create**

13. Create a second **Session policy** called *Protect download to
     unmanaged devices.*

14. In the **Session control type** field Select **Control file download
     (with DLP)** 

	 ![xsznq6n8.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/xsznq6n8.jpg)

15. Under **Activity source** in the **Activities matching all of the
     following** section, select the following activity filters to
     apply to the policy:

 **Device tags** does not equal **Valid client certificate**

 **App** equals **Salesforce**

 ![8s4bu84k.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/8s4bu84k.jpg)

16. Clear the **Enabled** checkbox near **Content inspection**

17. Under **Actions**, select **Protect**

    ![c5xhnr87.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/c5xhnr87.jpg)

18. Click on **Create**

19. Disable this policy

### Test the user experience

1.  Extract the file **silvia.pfx** from the **Client Certificate**
     folder in **Demo files.zip** file you've received

2.  Double click on the **silvia.pfx** file, click **Next**, **Next**,
     enter the password **acme**, click **Next**, **Next**, **Finish**.

3.  Open a new browser in an Incognito mode

4.  Go to <https://myapps.microsoft.com> and login with the admin user

5.  Click on the **SalesforceCAS** tile

6.  You should now see a certificate prompt. Click on **Cancel**.

     [In a real demo]{.underline}, you can open two different browsers,
     side by side, and show the user experience from a managed and
     unmanaged device by clicking on **OK** in one browser and
     **Cancel** in the other.

   ![2mj216sm.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/2mj216sm.jpg)

7.  You should then see a Monitored access message, click on **Continue
     to Salesforce** to continue.

    ![h2oyt9fw.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/h2oyt9fw.jpg)

8.  Now you are logged in to Salesforce. Click on + and go to Files

    ![d0ik67yl.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/d0ik67yl.jpg)

9.  Upload the files **Personal employees information.docx** and
     **Protect with Microsoft Cloud App Security proxy.pdf** from the
     **Demo files.zip** file to the Files page in Salesforce

10. Download the **Protect with Microsoft Cloud App Security proxy.pdf**
     files and see that it is downloaded, and you can open it.

11. Download the **Personal employees information.docx** file and see
     that you get a blocking message and instead of the file, you get a
     Blocked...txt file.

   ![wvk16zl2.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/wvk16zl2.jpg)

### Test the admin experience

1.  Go back to the Cloud App Security portal, and under **Investigate**
    choose **Activity log**

2.  See the login activity that was redirected to the session control,
    the file download that was not blocked, and the file download that
    was blocked because it matched the policy.

    ![j0vuo06k.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/j0vuo06k.jpg)
===
# Management
[🔙](#microsoft-365-cloud-app-security)

### Estimated time to complete
30 min

### Manage admin access 

For this task, you are asked to delegate admin access to other users,
without adding them to the Global Admin management role.

Documentation:
<https://docs.microsoft.com/en-us/cloud-app-security/manage-admins>

#### Delegate user group administration

You are asked to delegate the management of MCAS for US employees to a
new administrator.

By following the explanations in the documentation you have to:

1.  Create a new administrator account "mcasAdminUS"

2.  Create a new Azure AD group "US employees" containing a couple of
    your test users (not your admin account)

3.  Delegate that group management in MCAS to "mcasAdminUS"

4.  Connect to MCAS with "mcasAdminUS" and compare the activities,
    alerts and actions that this admin can perform

#### Delegate MCAS administration to an external admin

As a Managed Security Service Providers (MSSPs), you are asked by your
customer how you could access their environment to manage their alerts
in the Cloud App Security portal.

As the MCAS admin for your company, work with the person next to you to
configure an external access for the Managed Security Service Provider.

### MCAS PowerShell module introduction

To help administrators interact with MCAS in a programmatic way, two
Microsoft employees created a non-official PowerShell module for Cloud
App Security. For this lab, you will install this module and discover
the available cmdlets.

Note: the module relies on the Cloud App Security API. You can find its
documentation in the MCAS portal.

![f847xhzx.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/f847xhzx.jpg)

The module is available in the PowerShell gallery and can be installed
using the *Install-Module mcas* command.

![6j16dgs2.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/6j16dgs2.jpg)

More information on the module is available on GitHub:
<https://github.com/powershellshock/MCAS-Powershell>

After installing the module, read how to connect to MCAS in the
PowerShell help and start exploring the cmdlets.

Hint: you'll have to create an API token in Cloud App Security.

![0x2tzeqd.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/0x2tzeqd.jpg)

Using PowerShell:

1.  Review the list of MCAS administrators and when they were granted
    those permissions

2.  Review your security alerts and close them in bulk

3.  Download a sample SQUID log and send it to MCAS as a snapshot
    report.

4.  In the portal, in Discovery, tag some apps as unsanctioned and
    generate a blocking script for your appliance to block access to
    those apps.

5.  You are asked to define corporate IP's in MCAS. Subnets go from
    10.50.50.0/24 to 10.50.80.0/24

===
# Azure Information Protection
[🔙](#introduction)
### Objectives

After completing this lab, you will be able to:

- [Configure the Azure Information Protection scanner to discover sensitive data](#exercise-1-configuring-aip-scanner-for-discovery)
- [Configure Azure Information Protection labels](#creating-configuring-and-modifying-sub-labels)
- [Configure Azure Information Protection policies](#configuring-global-policy)
- [Classify and protect content with Azure Information Protection in Office applications](#configuring-applications)
- [Configure Exchange Online Mail Flow Rules for AIP](#configuring-exchange-online-mail-flow-rules)
- [Classify and protect sensitive data discovered by the AIP Scanner](#configuring-automatic-conditions)
- [Activate Unified Labeling for the Security and Compliance Center (Optional)](#security-and-compliance-center)
- [Configure SharePoint IRM Libraries (Optional)](#exercise-5-sharePoint-irm-configuration)

===

# Exercise 1: Configuring AIP Scanner for Discovery
[🔙](#azure-information-protection)

Even before configuring an AIP classification taxonomy, customers can scan and identify files containing sensitive information based on the built-in sensitive information types included in the Microsoft Classification Engine.  

![ahwj80dw.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/ahwj80dw.jpg)

Often, this can help drive an appropriate level of urgency and attention to the risk customers face if they delay rolling out AIP classification and protection.  

In this exercise, we will install the AIP scanner and run it against repositories in discovery mode.  Later in this lab (after configuring labels and conditions) we will revisit the scanner to perform automated classification, labeling, and protection of sensitive documents.

===
# Configuring Azure Log Analytics
[🔙](#azure-information-protection)

In order to collect log data from Azure Information Protection clients and services, you must first configure the log analytics workspace.

1. [] Switch to the **@lab.VirtualMachine(AdminPC).SelectLink** virtual machine.

1. [] Log in using the Username and Password below:

	+++Nuck Chorris+++

	+++Pa$$w0rd+++

1. [] Right-click on **Edge** in the taskbar and click on **New InPrivate window**.
	>
	>![jnblioyn.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/jnblioyn.jpg)
	>
1. [] In the InPrivate window, navigate to +++https://portal.azure.com/+++
	>
	>^IMAGE[Open Screenshot](cznh7i2b.jpg)

1. [] Log in using the username and password below:
	
	+++@lab.CloudCredential(81).Username+++ 
	
	+++@lab.CloudCredential(81).Password+++

	^IMAGE[Open Screenshot](gerhxqeq.jpg)

1. [] After logging into the portal, type the word +++info+++ into the **search bar** and press **Enter**, then click on **Azure Information Protection**. 

	![2598c48n.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/2598c48n.jpg)
	
	> [!HINT] If you do not see the search bar at the top of the portal, click on the **Magnifying Glass** icon to expand it.
	>
	> ![ny3fd3da.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/ny3fd3da.jpg)

	>![52a7iwuj.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/52a7iwuj.jpg)
===

# Connecting to Azure AD and Creating Service Account
[🔙](#azure-information-protection)

In this task, we will connect to Azure AD Powershell using the provided tenant credentials and create a cloud based service account for use with the Azure Information Protection scanner.

1. [] Switch to @lab.VirtualMachine(Scanner01).SelectLink and (if necessary) log in using the username and password below:

	+++@lab.VirtualMachine(Scanner01).Username+++ 
	
	+++@lab.VirtualMachine(Scanner01).Password+++

1. [] Right-click on the **PowerShell** icon in the taskbar and click on **Run as Administrator**.

	![7to6p334.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/7to6p334.jpg)
1. [] In PowerShell, run +++Connect-AzureAD+++ and use the username and password below. 
	
	+++@lab.CloudCredential(81).Username+++
	
	+++@lab.CloudCredential(81).Password+++

1. [] Next, we must build the PasswordProfile object to define the parameters needed when creating the password for the cloud service account.  This is done by running the commands below.

    +++$PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile+++

    +++$PasswordProfile.Password = "Somepass1"+++

    +++$PasswordProfile.ForceChangePasswordNextLogin = $false+++

1. [] Now, we can create the cloud service account using the command below.

    +++New-AzureADUser -AccountEnabled $True -DisplayName "AIP Scanner Cloud Service" -PasswordProfile $PasswordProfile -MailNickName "AIPScanner" -UserPrincipalName "AIPScanner@@lab.CloudCredential(81).TenantName"+++

===

# Installing the AIP Scanner Service
[🔙](#azure-information-protection)

The first step in configuring the AIP Scanner is to install the service and connect the database.  This is done with the Install-AIPScanner cmdlet that is provided by the AIP Client software.  The AIPScanner service account has been pre-staged in Active Directory for convenience.

1. [] At the PowerShell prompt, type +++$SQL = "Scanner01"+++
1. [] Next, type +++Install-AIPScanner -SQLServerInstance $SQL+++ and press **Enter**.
1. [] When prompted, provide the credentials for the AIP scanner service account.
	
	+++Contoso\AIPScanner+++

	+++Somepass1+++

	^IMAGE[Open Screenshot](pc9myg9x.jpg)

	> [!knowledge] You should see a success message like the one below. 
	>
	>![w7goqgop.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/w7goqgop.jpg)
	>

1. [] Right-click on the **Windows** button in the lower left-hand corner and click on **Run**.
1. [] In the Run dialog, type +++Services.msc+++ and click **OK**.

	^IMAGE[Open Screenshot](h0ys0h4u.jpg)
1. [] In the Services console, double-click on the **Azure Information Protection Scanner** service.
1. [] On the **Log On** tab of the Azure Information Protection Scanner Service Properties, verify that **Log on as:** is set to the **Contoso\AIPScanner** service account.

	^IMAGE[Open Screenshot](ek9jsd0a.jpg)

===

# Creating Azure AD Applications for the AIP Scanner
[🔙](#azure-information-protection)

Now that you have installed the scanner bits, you need to get an Azure AD token for the scanner service account to authenticate so that it can run unattended. This requires registering both a Web app and a Native app in Azure Active Directory.  The commands below will do this in an automated fashion rather than needing to go into the Azure portal directly.

1. [] At the PowerShell prompt, **type the commands below** and press **Enter** to create a new Web App Registration and Service Principal in Azure AD.

   ```
   New-AzureADApplication -DisplayName AIPOnBehalfOf -ReplyUrls http://localhost
   $WebApp = Get-AzureADApplication -Filter "DisplayName eq 'AIPOnBehalfOf'"
   New-AzureADServicePrincipal -AppId $WebApp.AppId
   $WebAppKey = New-Guid
   $Date = Get-Date
   New-AzureADApplicationPasswordCredential -ObjectId $WebApp.ObjectID -startDate $Date -endDate $Date.AddYears(1) -Value $WebAppKey.Guid -CustomKeyIdentifier "AIPClient"
	```
1. [] Next, we must build the permissions object for the Native App Registration.  This is done using the commands below.
   
   ```
   $AIPServicePrincipal = Get-AzureADServicePrincipal -All $true | ? {$_.DisplayName -eq 'AIPOnBehalfOf'}
   $AIPPermissions = $AIPServicePrincipal | select -expand Oauth2Permissions
   $Scope = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList $AIPPermissions.Id,"Scope"
   $Access = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
   $Access.ResourceAppId = $WebApp.AppId
   $Access.ResourceAccess = $Scope
	```
1. [] Next, we will use the object created above to create the Native App Registration.
   
   ```
   New-AzureADApplication -DisplayName AIPClient -ReplyURLs http://localhost -RequiredResourceAccess $Access -PublicClient $true
   $NativeApp = Get-AzureADApplication -Filter "DisplayName eq 'AIPClient'"
   New-AzureADServicePrincipal -AppId $NativeApp.AppId
	```
   
1. [] Finally, we will output the Set-AIPAuthentication command by running the commands below.
   
   ```
   "Set-AIPAuthentication -WebAppID " + $WebApp.AppId + " -WebAppKey " + $WebAppKey.Guid + " -NativeAppID " + $NativeApp.AppId | Out-File C:\Scripts\Set-AIPAuthentication.txt
	Start c:\Scripts\Set-AIPAuthentication.txt
	```
1. [] Copy the command to the clipboard.
1. [] Click on the Start menu and type +++PowerShell+++, right-click on the PowerShell program, and click **Run as a different user**.

	![zgt5ikxl.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/zgt5ikxl.jpg)

1. [] When prompted, enter the username and password below and click **OK**.

	+++Contoso\AIPScanner+++ 

	+++Somepass1+++

1. [] Paste the copied **Set-AIPAuthentication** command into this window and run it.
1. [] When prompted, enter the username and password below:

	+++AIPScanner@@lab.CloudCredential(81).TenantName+++

	+++Somepass1+++

	^IMAGE[Open Screenshot](qfxn64vb.jpg)

1. [] In the Permissions requested window, click **Accept**.

   ![nucv27wb.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/nucv27wb.jpg)
   
	>[!knowledge] You will a message like the one below in the PowerShell window once complete.
	>
	>![y2bgsabe.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/y2bgsabe.jpg)
1. [] In the PowerShell window, type the command below and press **Enter**.

	+++Restart-Service AIPScanner+++
   
===

# Configuring Repositories
[🔙](#azure-information-protection)

In this task, we will configure repositories to be scanned by the AIP scanner.  As previously mentioned, these can be any type of CIFS file shares including NAS devices sharing over the CIFS protocol.  Additionally, On premises SharePoint 2010, 2013, and 2016 document libraries and lists (attachements) can be scanned.  You can even scan entire SharePoint sites by providing the root URL of the site.  There are several optional 

> [!NOTE] SharePoint 2010 is only supported for customers who have extended support for that version of SharePoint.

The next task is to configure repositories to scan.  These can be on-premises SharePoint 2010, 2013, or 2016 document libraries and any accessible CIFS based share.

1. [] In the PowerShell window on Scanner01 run the commands below

    ```
    Add-AIPScannerRepository -Path http://Scanner01/documents -SetDefaultLabel Off
	```
	```
	Add-AIPScannerRepository -Path \\Scanner01\documents -SetDefaultLabel Off
    ```
	>[!Knowledge] Notice that we added the **-SetDefaultLabel Off** switch to each of these repositories.  This is necessary because our Global policy has a Default label of **General**.  If we did not add this switch, any file that did not match a condition would be labeled as General when we do the enforced scan.

	^IMAGE[Open Screenshot](00niixfd.jpg)
1. [] To verify the repositories configured, run the command below.
	
    ```
    Get-AIPScannerRepository
    ```
	^IMAGE[Open Screenshot](n5hj5e7j.jpg)

===

# Running Sensitive Data Discovery
[🔙](#azure-information-protection)

1. [] Run the commands below to run a discovery cycle.

    ```
	Set-AIPScannerConfiguration -DiscoverInformationTypes All -Enforce Off
	```
	```
	Start-AIPScan
    ```

	> [!Knowledge] Note that we used the DiscoverInformationTypes -All switch before starting the scan.  This causes the scanner to use any custom conditions that you have specified for labels in the Azure Information Protection policy, and the list of information types that are available to specify for labels in the Azure Information Protection policy.  Although the scanner will discover documents to classify, it will not do so because the default configuration for the scanner is Discover only mode.
 	
1. [] Right-click on the **Windows** button in the lower left-hand corner and click on **Event Viewer**.
 
	^IMAGE[Open Screenshot](cjvmhaf0.jpg)
1. [] Expand **Application and Services Logs** and click on **Azure Information Protection**.

	^IMAGE[Open Screenshot](dy6mnnpv.jpg)
 
	>[!NOTE] You will see an event like the one below when the scanner completes the cycle.
	>
	>![o46iabfu.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/o46iabfu.jpg)
 
1. [] Next, switch to @lab.VirtualMachine(AdminPC).SelectLink browse to +++\\\Scanner01\c$\users\aipscanner\AppData\Local\Microsoft\MSIP\Scanner\Reports+++ and review the summary txt and detailed csv files available there.  

	>[!Hint] Since there are no Automatic conditions configured yet, the scanner found no matches for the 100 files scanned despite 96 of them having sensitive data.
	>
	>![m79emvr8.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/m79emvr8.jpg)
	>
	>The details contained in the DetailedReport.csv can be used to identify the types of sensitive data you need to create AIP rules for in the Azure Portal.
	>
	>![9y52ab7u.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/9y52ab7u.jpg)

1. [] Next, back in the Azure portal, under **Dashboards**, click on Data discovery (preview) and review the data collected in the report.  

	>[!NOTE] It may take several minutes for all data to display in the report.  You can see the various types of sensitive data that was discovered in the repositories that we configured.  We have not actively configured any policies at this point, so no files will be labeled or protected. We will do that in a later exercise in the lab.

	>![52a7iwuj.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/52a7iwuj.jpg)

===

# Exercise 2: Configuring Azure Information Protection Policy
[🔙](#azure-information-protection)

This exercise demonstrates using the Azure Information Protection blade in the Azure portal to configure policies and sub-labels.  We will create a new sub-label and configure protection and then modify an existing sub-label.  We will also create a label that will be scoped to a specific group.  

We will next configure AIP Global Policy to use the General sub-label as default, and finally, we will configure a scoped policy to use the new scoped label by default for Word, Excel, and PowerPoint while still using General as default for Outlook.
===
# Creating, Configuring, and Modifying Sub-Labels
[🔙](#azure-information-protection)

In this task, we will configure a label protected for internal audiences that can be used to help secure sensitive data within your company.  By limiting the audience of a specific label to only internal employees, you can dramatically reduce the risk of unintentional disclosure of sensitive data and help reduce the risk of successful data exfiltration by bad actors.  However, there are times when external collaboration is required, so we will configure a label to match the name and functionality of the Do Not Forward button in Outlook.  This will allow users to more securely share sensitive information outside the company to any recipient.  By using the name Do Not Forward, the functionality will also be familiar to what previous users of AD RMS or Azure RMS may have used in the past.

1. [] Switch to the **@lab.VirtualMachine(AdminPC).SelectLink** virtual machine.

1. [] If necessary, log in using the Username and Password below:

	+++Nuck Chorris+++

	+++Pa$$w0rd+++

1. [] Right-click on **Edge** in the taskbar and click on **New InPrivate window**.
	
	![jnblioyn.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/jnblioyn.jpg)
	
1. [] In the InPrivate window, navigate to +++https://portal.azure.com/+++
	
	^IMAGE[Open Screenshot](cznh7i2b.jpg)

1. [] Log in using the username and password below:
	
	+++@lab.CloudCredential(81).Username+++ 
	
	+++@lab.CloudCredential(81).Password+++

	^IMAGE[Open Screenshot](gerhxqeq.jpg)

1. [] After logging into the portal, type the word +++info+++ into the **search bar** and press **Enter**, then click on **Azure Information Protection**. 

	![2598c48n.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/2598c48n.jpg)
	
	> [!HINT] If you do not see the search bar at the top of the portal, click on the **Magnifying Glass** icon to expand it.
	>
	> ![ny3fd3da.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/ny3fd3da.jpg)


1. [] Under **classifications** in the left pane, click on **Labels** to load the Azure Information Protection – Labels blade.

	^IMAGE[Open Screenshot](mhocvtih.jpg)

1. [] In the Azure Information Protection – Labels blade, right-click on **Confidential** and click **Add a sub-label**.

	^IMAGE[Open Screenshot](uktfuwuk.jpg)

1. [] In the Sub-label blade, type +++Contoso Internal+++ for the **Label display name** and for **Description** enter text similar to +++Confidential data that requires protection, which allows Contoso Internal employees full permissions. Data owners can track and revoke content.+++

	^IMAGE[Open Screenshot](4luorc0u.jpg)

1. [] Then, under **Set permissions for documents and emails containing this label**, click **Protect**, and under **Protection**, click on **Azure (cloud key)**.

	^IMAGE[Open Screenshot](tp97a19d.jpg)

1. [] In the Protection blade, click **+ Add Permissions**.

	^IMAGE[Open Screenshot](layb2pvo.jpg)

1. [] In the Add permissions blade, click on **+ Add contoso – All members** and click **OK**.

	^IMAGE[Open Screenshot](zc0iuoyz.jpg)

1. [] In the Protection blade, click **OK**.

	^IMAGE[Open Screenshot](u8jv46zo.jpg)

1. [] In the Sub-label blade, scroll down to the **Set visual marking (such as header or footer)** section and under **Documents with this label have a header**, click **On**.

	> Use the values in the table below to configure the Header.

	| Setting          | Value            |
	|:-----------------|:-----------------|
	| Header text      | +++Contoso Internal+++ |
	| Header font size | +++24+++               |
	| Header color     | Purple           |
	| Header alignment | Center           |

	> [!NOTE] These are sample values to demonstrate marking possibilities and **NOT** a best practice.

	^IMAGE[Open Screenshot](0vdoc6qb.jpg)

1. [] To complete creation of the new sub-label, click the **Save** button and then click **OK** in the Save settings dialog.

	^IMAGE[Open Screenshot](89nk9deu.jpg)

1. [] In the Azure Information Protection - Labels blade, expand **Confidential** (if necessary) and then click on **Recipients Only**.

	^IMAGE[Open Screenshot](eiiw5zbg.jpg)

1. [] In the Label: Recipients Only blade, change the **Label display name** from **Recipients Only** to +++Do Not Forward+++.

	^IMAGE[Open Screenshot](v54vd4fq.jpg)

1. [] Next, in the **Set permissions for documents and emails containing this label** section, under **Protection**, click **Azure (cloud key): User defined**.

	^IMAGE[Open Screenshot](qwyranz0.jpg)

1. [] In the Protection blade, under **Set user-defined permissions (Preview)**, verify that only the box next to **In Outlook apply Do Not Forward** is checked, then click **OK**.

	^IMAGE[Open Screenshot](16.png)

	> [!knowledge] Although there is no action added during this step, it is included to show that this label will only display in Outlook and not in Word, Excel, PowerPoint or File Explorer.

1. [] Click **Save** in the Label: Recipients Only blade and **OK** to the Save settings prompt. 

	^IMAGE[Open Screenshot](9spkl24i.jpg)

1. []  Click the **X** in the upper right corner of the blade to close.

	^IMAGE[Open Screenshot](98pvhwdv.jpg)

===

# Configuring Global Policy
[🔙](#azure-information-protection)

In this task, we will assign the new sub-label to the Global policy and configure several global policy settings that will increase Azure Information Protection adoption among your users and reduce ambiguity in the user interface.

1. [] In the Azure Information Protection blade, under **classifications** on the left, click **Policies** then click the **Global** policy.

	^IMAGE[Open Screenshot](24qjajs5.jpg)

1. [] In the Policy: Global blade, below the labels, click **Add or remove labels**.

1. [] In the Policy: Add or remove labels blade, check the boxes next to **All Labels except the last 3** and click **OK**.

	![d0pxo2m6.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/d0pxo2m6.jpg)

1. [] In the Policy: Global blade, under the **Configure settings to display and apply on Information Protection end users** section, configure the policy to match the settings shown in the table and image below.

	| Setting | Value |
	|:--------|:------|
	| Select the default label | General |
	|All documents and emails must have a label…|On
	Users must provide justification to set a lower…|On
	For email messages with attachments, apply a label…|Automatic
	Add the Do Not Forward button to the Outlook ribbon|Off

	![Open Screenshot](mtqhe3sj.jpg)

1. [] Click **Save**, then **OK** to complete configuration of the Global policy.

	^IMAGE[Open Screenshot](1p1q4pxe.jpg)

1. [] Click the **X** in the upper right corner to close the Policy: Global blade.

	^IMAGE[Open Screenshot](m6e4r2u2.jpg)

===

# Creating a Scoped Label and Policy
[🔙](#azure-information-protection)

Now that you have learned how to work with global labels and policies, we will create a new scoped label and policy for the Legal team at Contoso.  (If you are using your own demo tenant you may need to create the users and described.)

1. [] Under **classifications** on the left, click **Labels**.

	^IMAGE[Open Screenshot](50joijwb.jpg)

1. [] In the Azure Information Protection – Labels blade, right-click on **Highly-Confidential** and click **Add a sub-label**.

	^IMAGE[Open Screenshot](tasz9t0i.jpg)

1. [] In the Sub-label blade, enter +++Legal Only+++ for the **Label display name** and for **Description** enter +++Data is classified and protected. Legal department staff can edit, forward and unprotect.+++.

	^IMAGE[Open Screenshot](lpvruk49.jpg)

1. [] Then, under **Set permissions for documents and emails containing this label**, click **Protect** and under **Protection**, click **Azure (cloud key)**.

	^IMAGE[Open Screenshot](6ood4jqu.jpg)

1. [] In the Protection blade, under **Protection settings**, click the **+ Add permissions** link.

	![ozzumi7l.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/ozzumi7l.jpg)

1. [] In the Add permissions blade, click **+ Browse directory**.

	^IMAGE[Open Screenshot](2lvwim24.jpg)

1. [] In the AAD Users and Groups blade, **wait for the names to load**, then check the boxes next to **Alan Steiner** and **Amy Albers**, and click the **Select** button.

	^IMAGE[Open Screenshot](uishk9yh.jpg)

	> [!Note] In a production environment, you will typically use a synced or Azure AD Group rather than choosing individuals.

1. [] In the Add permissions blade, click **OK**.

	^IMAGE[Open Screenshot]![stvnaf4f.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/stvnaf4f.jpg)

1. [] In the Protection blade, under **Allow offline access**, reduce the **Number of days the content is available without an Internet connection** value to +++3+++ and press **OK** .

	> [!Knowledge] This value determines how many days a user will have offline access from the time a document is opened, and an initial Use License is acquired.  While this provides convenience for users, it is recommended that this value be set appropriately based on the sensitivity of the content.

	^IMAGE[Open Screenshot](j8masv1q.jpg)

1. [] Click **Save** in the Sub-label blade and **OK** to the Save settings prompt to complete the creation of the Legal Only sub-label.

	^IMAGE[Open Screenshot](dfhoii1x.jpg)

1. [] In the Azure Information Protection blade, under **Classifications** on the left, click **Policies** then click the **+Add a new policy** link.

	^IMAGE[Open Screenshot](ospsddz6.jpg)

1. [] In the Policy blade, for Policy name, type +++Legal Scoped Policy+++ and click on **Select which users or groups get this policy. Groups must be email-enabled.**

	![tosu2a6j.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/tosu2a6j.jpg)

1. [] In the AAD Users and Groups blade, click on **Users/Groups**.  
1. [] Then in the second AAD Users and Groups blade, **wait for the names to load** and check the boxes next to **Alan Steiner** and **Amy Albers**.
1. [] Click the **Select** button.
1. [] Finally, click **OK**.

	^IMAGE[Open Screenshot](onne7won.jpg)

1. [] In the Policy blade, under the labels, click on **Add or remove labels** to add the scoped label.

	![b6e9nbui.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/b6e9nbui.jpg)

1. [] In the Policy: Add or remove labels blade, check the box next to **Legal Only** and click **OK**.

	^IMAGE[Open Screenshot](c2429kv9.jpg)

1. [] In the Policy blade, under **Configure settings to display and apply on Information Protection end users** section, under **Select the default label**, select **None** as the default label for this scoped policy.

	![6sh1sfz5.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/6sh1sfz5.jpg)

1. [] Click **Save**, then **OK** to complete creation of the Legal Scoped Policy.

	^IMAGE[Open Screenshot](41jembjf.jpg)

1. [] Click on the **X** in the upper right-hand corner to close the policy.

===

# Configuring Advanced Policy Settings
[🔙](#azure-information-protection)

There are many advanced policy settings that are useful to tailor your Azure Information Protection deployment to the needs of your environment.  In this task, we will cover one of the settings that is very complimentary when using scoped policies that have a protected default label.  Because the Legal Scoped Policy we created in the previous task uses a protected default label, we will be adding an alternate default label for Outlook to provide a more palatable user experience for those users.

1. [] In the Azure Information Protection blade, under **classifications** on the left, click on **Labels** and then click on the **General** label.

    ^IMAGE[Open Screenshot](rvn4xorx.jpg)

1. [] In the Label: General blade, scroll to the bottom and copy the **Label ID** and close the blade using the **X** in the upper right-hand corner.

    ![8fi1wr4d.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/8fi1wr4d.jpg)

1. [] In the AIP Portal, under **classifications** on the left, click on **Policies**. Right-click on the **Legal Scoped Policy** and click on **Advanced settings**.

    ^IMAGE[Open Screenshot](2jo71ugb.jpg)

1. [] In the Advanced settings blade, in the textbox under **NAME**, type +++OutlookDefaultLabel+++.  In the textbox under **VALUE**, paste the **Label ID** for the **General** label you copied previously, then click **Save and close**.

    > [!ALERT] CAUTION: Please check to ensure that there are **no spaces** before or after the **Label ID** when pasting as this will cause the setting to not apply.

    ![ezt8sfs3.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/ezt8sfs3.jpg)

	> [!HINT] This and additional Advanced Policy Settings can be found at https://docs.microsoft.com/en-us/azure/information-protection/rms-client/client-admin-guide-customizations 

===

# Defining Recommended and Automatic Conditions
[🔙](#azure-information-protection)

One of the most powerful features of Azure Information Protection is the ability to guide your users in making sound decisions around safeguarding sensitive data.  This can be achieved in many ways through user education or reactive events such as blocking emails containing sensitive data. However, helping your users to properly classify and protect sensitive data at the time of creation is a more organic user experience that will achieve better results long term.  In this task, we will define some basic recommended and automatic conditions that will trigger based on certain types of sensitive data.

1. [] Under **classifications** on the left, click **Labels** then expand **Confidential**, and click on **Contoso Internal**.

	^IMAGE[Open Screenshot](jyw5vrit.jpg)
1. [] In the Label: Contoso Internal blade, scroll down to the **Configure conditions for automatically applying this label** section, and click on **+ Add a new condition**.

	![cws1ptfd.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/cws1ptfd.jpg)
1. [] In the Condition blade, in the **Select information types** search box, type +++credit+++ and check the box next to **Credit Card Number**.

	^IMAGE[Open Screenshot](9rozp61b.jpg)
1. [] Click **Save** in the Condition blade and **OK** to the Save settings prompt.

	^IMAGE[Open Screenshot](41o5ql2y.jpg)

	> [!Knowledge] By default the condition is set to Recommended and a policy tip is created with standardized text.
	>
	>  ![qdqjnhki.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/qdqjnhki.jpg)

1. [] Click **Save** in the Label: Contoso Internal blade and **OK** to the Save settings prompt.

	^IMAGE[Open Screenshot](rimezmh1.jpg)
1. [] Press the **X** in the upper right-hand corner to close the Label: Contoso Internal blade.

	^IMAGE[Open Screenshot](em124f66.jpg)
1. [] Next, expand **Highly Confidential** and click on the **All Employees** sub-label.

	^IMAGE[Open Screenshot](2eh6ifj5.jpg)
1. [] In the Label: All Employees blade, scroll down to the **Configure conditions for automatically applying this label** section, and click on **+ Add a new condition**.

	^IMAGE[Open Screenshot](8cdmltcj.jpg)
1. [] In the Condition blade, click on **Custom** and enter +++Password+++ for the **Name** and in the textbox below **Match exact phrase or pattern**, type +++pass@word1+++.

	![ra7dnyg6.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/ra7dnyg6.jpg)
1. [] Click **Save** in the Condition blade and **OK** to the Save settings prompt.

	^IMAGE[Open Screenshot](ie6g5kta.jpg)
1. [] In the Labels: All Employees blade, in the **Configure conditions for automatically applying this label** section, click **Automatic**.

	![245lpjvk.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/245lpjvk.jpg)
	> [!HINT] The policy tip is automatically updated when you switch the condition to Automatic.
1. [] Click **Save** in the Label: All Employees blade and **OK** to the Save settings prompt.

	^IMAGE[Open Screenshot](gek63ks8.jpg)
1. [] Press the **X** in the upper right-hand corner to close the Label: All Employees blade.

	^IMAGE[Open Screenshot](wzwfc1l4.jpg)

===

# Exercise 2: Client and Exchange Configuration
[🔙](#azure-information-protection)

Now that we have defined some basic AIP Policies, we need to configure some clients to demonstrate the Discovery, Classification, and Protection capabilities of Azure Information Protection.  In this exercise, we will configure Office 365 Applications for 3 test users to demonstrate these policy actions.  

Office 365 and the latest GA AIP Client (1.37.19.0) have already been installed on these systems to save time in this lab.  In your production environment, you will need to install the AIP Client manually for testing or using an Enterprise Deployment Tool like System Center Configuration Manager for widespread deployment.

We will also be disabling a mail flow rule in the Exchange Admin Center to allow mail to be sent outside the tenant.  This will allow us to test Do Not Forward and Office 365 Message Encryption scenarios.
===
# Configuring Applications
[🔙](#azure-information-protection)
![52a7iwuj.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/52a7iwuj.jpg)
In this task, we will configure Word and Outlook for 3 test users.  These users are Alan Steiner (AlanS) and Amy Alberts (AmyA) who we have defined as members of the Legal group, and Eric Grimes (EricG).  This will allow us to demonstrate the differences between the global and scoped policy and demonstrate some of the protection features of Azure Information Protection in the next exercise.

1. [] On @lab.VirtualMachine(Client01).SelectLink, minimize the Edge window and @[Click here](`"C:\\Program Files (x86)\\Microsoft Office\\root\\Office16\\WINWORD.EXE"`) to launch **Microsoft Word** (This may take a few seconds).

	> [!Hint] If the automation does not work, start **Microsoft Word** by clicking on the icon in the taskbar.
	>
	>![pxyal6hb.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/pxyal6hb.jpg)
	
	> [!knowledge] When Word opens, you may see a prompt to log into **Microsoft Azure Information Protection**.  You may **close this** and continue.  Azure Information Protection will automatically inherit the settings from Word after reloading.
	>
	> ![3gm9oeee.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/3gm9oeee.jpg)

1. [] In the Sign in set up Office dialog, click Sign in.
	
	^IMAGE[Open Screenshot](4yb3mnd1.jpg)
1. [] In the Activate Office dialog, enter +++AlanS@@lab.CloudCredential(81).TenantName+++ and press **Next**. 

1. [] In the Enter password dialog, enter +++pass@word1+++ and click **Sign in**.

1. [] In the Use this account everywhere on your device dialog, click **Yes**.

	^IMAGE[Open Screenshot](m1e7l6ei.jpg)

1. [] Finally, click **Done** to complete the setup.
1. [] Wait for the Getting Office ready for you dialog to close and then **Close Microsoft Word**
1. [] Next, @[Click here](`"C:\\Program Files (x86)\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"`) to start **Microsoft Outlook** or click on the icon in the taskbar.

	![vlu3sb64.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/vlu3sb64.jpg)
1. [] Click **Connect** and let Outlook configure.  

	> [!KNOWLEDGE] Login details for **AlanS@@lab.CloudCredential(81).TenantName** should be automatically populated. If you still see **Install@Contoso.com**, close Microsoft Outlook and reopen.
	>
	> If you receive a prompt to choose an account type, click Office 365.
	>
	> ![13mp3hbw.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/13mp3hbw.jpg)

1. [] **Uncheck** the box to **Set up Outlook Mobile on my phone**, too and click **OK**.

	![hjmvdzvv.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/hjmvdzvv.jpg)

1. [] Switch to **@lab.VirtualMachine(Client02).SelectLink** and and @[Click here](`"C:\\Program Files (x86)\\Microsoft Office\\root\\Office16\\WINWORD.EXE"`) to launch **Microsoft Word** (This may take a few seconds).

	> [!Hint] If the automation does not work, start **Microsoft Word** by clicking on the icon in the taskbar.
	>
	>![pxyal6hb.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/pxyal6hb.jpg)
	
	> [!knowledge] When Word opens, you may see a prompt to log into **Microsoft Azure Information Protection**.  You may **close this** and continue.  Azure Information Protection will automatically inherit the settings from Word after reloading.
	>
	> ![3gm9oeee.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/3gm9oeee.jpg)

1. [] In the Sign in set up Office dialog, click Sign in.
	
	^IMAGE[Open Screenshot](4yb3mnd1.jpg)
1. [] In the Activate Office dialog, enter +++AmyA@@lab.CloudCredential(81).TenantName+++ and press **Next**. 

1. [] In the Enter password dialog, enter +++pass@word1+++ and click **Sign in**.

1. [] In the Use this account everywhere on your device dialog, click **Yes**.

	^IMAGE[Open Screenshot](m1e7l6ei.jpg)

1. [] Finally, click **Done** to complete the setup.
1. [] Wait for the Getting Office ready for you dialog to close and then **Close Microsoft Word**
1. [] Next, @[Click here](`"C:\\Program Files (x86)\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"`) to start **Microsoft Outlook** or click on the icon in the taskbar.

	![vlu3sb64.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/vlu3sb64.jpg)
1. [] Click **Connect** and let Outlook configure.  

	> [!KNOWLEDGE] Login details for **AmyA@@lab.CloudCredential(81).TenantName** should be automatically populated. If you still see **Install@Contoso.com**, close Microsoft Outlook and reopen.
	>
	> If you receive a prompt to choose an account type, click Office 365.
	>
	> ![13mp3hbw.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/13mp3hbw.jpg)

1. [] **Uncheck** the box to **Set up Outlook Mobile on my phone**, too and click **OK**.

	^IMAGE[Open Screenshot](amepnw76.jpg)

1. [] Switch to **@lab.VirtualMachine(Client03).SelectLink** and @[Click here](`"C:\\Program Files (x86)\\Microsoft Office\\root\\Office16\\WINWORD.EXE"`) to launch **Microsoft Word** (This may take a few seconds).

	> [!Hint] If the automation does not work, start **Microsoft Word** by clicking on the icon in the taskbar.
	>
	>![pxyal6hb.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/pxyal6hb.jpg)
	
	> [!knowledge] When Word opens, you may see a prompt to log into **Microsoft Azure Information Protection**.  You may **close this** and continue.  Azure Information Protection will automatically inherit the settings from Word after reloading.
	>
	> ![3gm9oeee.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/3gm9oeee.jpg)

1. [] In the Sign in set up Office dialog, click Sign in.
	
	^IMAGE[Open Screenshot](4yb3mnd1.jpg)
1. [] In the Activate Office dialog, enter +++EricG@@lab.CloudCredential(81).TenantName+++ and press **Next**. 

1. [] In the Enter password dialog, enter +++pass@word1+++ and click **Sign in**.

1. [] In the Use this account everywhere on your device dialog, click **Yes**.

	^IMAGE[Open Screenshot](m1e7l6ei.jpg)

1. [] Finally, click **Done** to complete the setup.
1. [] Wait for the Getting Office ready for you dialog to close and then **Close Microsoft Word**
1. [] Next, @[Click here](`"C:\\Program Files (x86)\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"`) to start **Microsoft Outlook** or click on the icon in the taskbar.

	![vlu3sb64.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/vlu3sb64.jpg)
1. [] Click **Connect** and let Outlook configure.  

	> [!KNOWLEDGE] Login details for **EricG@@lab.CloudCredential(81).TenantName** should be automatically populated. If you still see **Install@Contoso.com**, close Microsoft Outlook and reopen.
	>
	> If you receive a prompt to choose an account type, click Office 365.
	>
	> ![13mp3hbw.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/13mp3hbw.jpg)

1. [] **Uncheck** the box to **Set up Outlook Mobile on my phone**, too and click **OK**.

	^IMAGE[Open Screenshot](hjmvdzvv.jpg)

===

# Disable Lab Default Exchange Online Mail Flow Rule
[🔙](#azure-information-protection)

1. [] Switch to **@lab.VirtualMachine(Client01).SelectLink**.

1. [] @[Click here](`cmd.exe/c start shell:AppsFolder\Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge -private https://outlook.office365.com/ecp/`) to launch the Exchange Admin Center.

	> [!knowledge] Right-click on **Edge** in the taskbar and click on **New InPrivate window**.
	>
	>![jnblioyn.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/jnblioyn.jpg)
	>In the InPrivate window, navigate to +++https://outlook.office365.com/ecp/+++.
	
1. [] Log in using +++@lab.CloudCredential(81).Username+++ and the password +++@lab.CloudCredential(81).Password+++.

1. [] In the Exchange admin center, click on **mail flow** on the left, then uncheck the box next to **Delete if sent outside the organization**.

	![kgoqkfrs.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/kgoqkfrs.jpg)
1. [] Wait for the view to update showing the disabled rule, then **minimize this window** and save it for when we add new rules in Exercise 4.

===

# Exercise 3: Testing AIP Policies
[🔙](#azure-information-protection)

Now that you have 3 test systems with users being affected by different policies configured, we can start testing these policies.  This exercise will run through various scenarios to demonstrate the use of AIP global and scoped policies and show the functionality of recommended and automatic labeling.
===
# Testing User Defined Permissions
[🔙](#azure-information-protection)

One of the most common use cases for AIP is the ability to send emails using User Defined Permissions (Do Not Forward). In this task, we will send an email using the Do Not Forward label to test that functionality.

1. [] Switch to @lab.VirtualMachine(Client03).SelectLink.
1. [] In Microsoft Outlook, click on the **New email** button.

	![6wan9me1.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/6wan9me1.jpg)

	> [!KNOWLEDGE] Note that the **Sensitivity** is set to **General** by default.
	>
	> ![5esnhwkw.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/5esnhwkw.jpg)

1. [] Send an email to Alan and Amy (+++AlanS;AmyA+++). You may optionally add an external email address (preferably from a major social provider like gmail, yahoo, or outlook.com) to test the external recipient experience. For the **Subject** and **Body** type +++Test Do Not Forward Email+++.

	^IMAGE[Open Screenshot](h0eh40nk.jpg)

1. [] In the Sensitivity Toolbar, click on the **pencil** icon to change the Sensitivity label.

	![901v6vpa.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/901v6vpa.jpg)

1. [] Click on **Confidential** and then the **Do Not Forward** sub-label and click **Send**.

	![w8j1w1lm.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/w8j1w1lm.jpg)

	> [!Knowledge] If you receive the error message below, click on the Confidential \ Contoso Internal sub-label to force the download of your AIP identity certificates, then follow the steps above to change the label to Confidential \ Do Not Forward.
	>
	> ![6v6duzbd.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/6v6duzbd.jpg)

1. [] Switch over to @lab.VirtualMachine(Client01).SelectLink or @lab.VirtualMachine(Client02).SelectLink and review the email in Alan or Amy’s Outlook.  You will notice that the email is automatically shown in Outlook natively.

	![0xby56qt.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/0xby56qt.jpg)

	> [!Hint] The **Do Not Forward** protection template will normally prevent the sharing of the screen and taking screenshots when protected documents or emails are loaded.  However, since this screenshot was taken within a VM, the operating system was unaware of the protected content and could not prevent the capture.  
	>
	>It is important to understand that although we put controls in place to reduce risk, if a user has view access to a document or email they can take a picture with their smartphone or even retype the message. That said, if the user is not authorized to read the message then it will not even render and we will demonstrate that next.

	> [!KNOWLEDGE] If you elected to send a Do Not Forward message to an external email, you will have an experience similar to the images below.  These captures are included to demonstrate the functionality for those that chose not to send an external message.
	>
	> ![tzj04wi9.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/tzj04wi9.jpg)
	> 
	> Here the user has received an email from Eric Grimes and they can click on the **Read the message** button.
	>
	>![wiefwcho.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/wiefwcho.jpg)
	>
	>Next, the user is given the option to either log in using the social identity provider (**Sign in with Google**, Yahoo, Microsoft Account), or to **sign in with a one-time passcode**.
	>
	>If they choose the social identity provider login, it should use the token previously cached by their browser and display the message directly.
	>
	>If they choose one-time passcode, they will receive an email like the one below with the one-time passcode.
	>
	>![m6voa9xi.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/m6voa9xi.jpg)
	>
	>They can then use this code to authenticate to the Office 365 Message Encryption portal.
	>
	>![8pllxint.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/8pllxint.jpg)
	>
	>After using either of these authentication methods, the user will see a portal experience like the one shown below.
	>
	>![3zi4dlk9.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/3zi4dlk9.jpg)
===

# Testing Global Policy
[🔙](#azure-information-protection)

In this task, we will create a document and send an email to demonstrate the functionality defined in the Global Policy.

1. [] Switch to @lab.VirtualMachine(Client03).SelectLink.
1. [] In Microsoft Outlook, click on the **New email** button.

	^IMAGE[Open Screenshot](6wan9me1.jpg)

1. [] Send an email to Alan, Amy, and yourself (+++AlanS;AmyA;@lab.User.Email+++).  For the **Subject** and **Body** type +++Test Contoso Internal Email+++.

	^IMAGE[Open Screenshot](9gkqc9uy.jpg)

1. [] In the Sensitivity Toolbar, click on the **pencil** icon to change the Sensitivity label.

	^IMAGE[Open Screenshot](901v6vpa.jpg)

1. [] Click on **Confidential** and then **Contoso Internal** and click **Send**.

	^IMAGE[Open Screenshot](yhokhtkv.jpg)
1. [] On @lab.VirtualMachine(Client01).SelectLink or @lab.VirtualMachine(Client02).SelectLink, observe that you are able to open the email natively in the Outlook client. Also observe the **header text** that was defined in the label settings.

	![bxz190x2.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/bxz190x2.jpg)
	
1. [] In your email, note that you will be unable to open this message.  This experience will vary depending on the client you use (the image below is from Outlook 2016 for Mac) but they should have similar messages after presenting credentials. Since this is not the best experience for the recipient, in Exercise 4, we will configure Exchange Online Mail Flow Rules to prevent content classified with internal only labels from being sent to external users.
	
	![52hpmj51.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/52hpmj51.jpg)

===

# Testing Scoped Policy
[🔙](#azure-information-protection)

In this task, we will create a document and send an email from one of the users in the Legal group to demonstrate the functionality defined in the first exercise. We will also show the behavior of the No Default Label policy on documents.

1. [] Switch to @lab.VirtualMachine(Client01).SelectLink.
1. [] In Microsoft Outlook, click on the **New email** button.
	
	^IMAGE[Open Screenshot](ldjugk24.jpg)
	
1. [] Send an email to Amy and Eric (+++AmyA;EricG+++).  For the **Subject** and **Body** type +++Test Highly Confidential Legal Email+++.
1. [] In the Sensitivity Toolbar, click on **Highly Confidential** and the **Legal Only** sub-label, then click **Send**.

	^IMAGE[Open Screenshot](ny1lwv0h.jpg)
1. [] Switch to @lab.VirtualMachine(Client02).SelectLink and click on the email.  You should be able to open the message natively in the client as AmyA.

	![qeqtd2yr.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/qeqtd2yr.jpg)
1. [] Switch to @lab.VirtualMachine(Client03).SelectLink and click on the email. You should be unable to open the message as EricG.

	![6y99u8cl.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/6y99u8cl.jpg)

	> [!Knowledge] You may notice that the Office 365 Message Encryption wrapper message is displayed in the preview pane.  It is important to note that the content of the email is not displayed here.  The content of the message is contained within the encrypted message.rpmsg attachment and only authorized users will be able to decrypt this attachment.
	>
	>![w4npbt49.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/w4npbt49.jpg)
	>
	>If an unauthorized recipient clicks on **Read the message** to go to the OME portal, they will be presented with the same wrapper message.  Like the external recipient from the previous task, this is not an ideal experience. So, you may want to use a mail flow rule to manage scoped labels as well.
	>
	>![htjesqwe.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/htjesqwe.jpg)

===

# Testing Recommended and Automatic Classification
[🔙](#azure-information-protection)

In this task, we will test the configured recommended and automatic conditions we defined in Exercise 1.  Recommended conditions can be used to help organically train your users to classify sensitive data appropriately and provides a method for testing the accuracy of your dectections prior to switching to automatic classification.  Automatic conditions should be used after thorough testing or with items you are certain need to be protected. Although the examples used here are fairly simple, in production these could be based on complex regex statements or only trigger when a specific quantity of sensitive data is present.

1. [] Switch to @lab.VirtualMachine(Client03).SelectLink and @[Click here](`"C:\\Program Files (x86)\\Microsoft Office\\root\\Office16\\WINWORD.EXE"`) to launch **Microsoft Word**.
1. [] In Microsoft Word, create a new **Blank document** and type +++My AMEX card number is 344047014854133. The expiration date is 09/28, and the CVV is 4368+++ and **save** the document.

	> [!NOTE] This card number is a fake number that was generated using the Credit Card Generator for Testing at https://developer.paypal.com/developer/creditCardGenerator/.  The Microsoft Classification Engine uses the Luhn Algorithm to prevent false positives so when testing, please make sure to use valid numbers.

1. [] Notice that you are prompted with a recommendation to change the classification to Confidential \ Contoso Internal. Click on **Change now** to set the classification and protect the document.

	![url9875r.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/url9875r.jpg)
	> [!Knowledge] Notice that, like the email in Task 2 of this exercise, the header value configured in the label is added to the document.
	>
	>![dcq31lz1.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/dcq31lz1.jpg)
1. [] In Microsoft Word, create a new **Blank document** and type +++my password is pass@word1+++ and **save** the document.

	>[!HINT] Notice that the document is automatically classified and protected wioth the Highly Confidential \ All Employees label.
	>
	>![6vezzlnj.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/6vezzlnj.jpg)
1. [] Next, in Microsoft Outlook, click on the **New email** button.
	
	^IMAGE[Open Screenshot](ldjugk24.jpg)
	
1. [] Draft an email to Amy and Alan (+++AmyA;AlanS+++).  For the **Subject** and **Body** type +++Test Highly Confidential All Employees Automation+++.

	^IMAGE[Open Screenshot](4v3wrrop.jpg)
1. [] Attach the **second document you created** to the email.

	![823tzyfd.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/823tzyfd.jpg)

	> [!HINT] Notice that the email was automatically classified as Highly Confidential \ All Employees.  This functionality is highly recommended because matching the email classification to attachments provides a much more cohesive user experience and helps to prevent inadvertent information disclosure in the body of sensitive emails.
	>
	>![yv0afeow.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/yv0afeow.jpg)

1. [] In the email, click **Send**.
===

# Exercise 4: Exchange Online IRM Capabilities
[🔙](#azure-information-protection)

Exchange Online can work in conjunction with Azure Information Protection to provide advanced capabilities for protecting sensitive data being sent over email.  You can also manage the flow of classified content to ensure that it is not sent to unintended recipients.  

# Configuring Exchange Online Mail Flow Rules
[🔙](#azure-information-protection)
![52a7iwuj.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/52a7iwuj.jpg)
In this task, we will configure a mail flow rule to detect credit card information traversing the network in the clear and encrypt it using the Encrypt Only RMS Template.  We will also create a mail flow rule to prevent messages classified as Confidential \ Contoso Internal from being sent to external recipients.

1. [] Switch to @lab.VirtualMachine(Client01).SelectLink and restore the **Exchange admin center** browser window.

	> [!HINT] If you closed the window, @[Click here](`cmd.exe/c start shell:AppsFolder\Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge -private https://outlook.office365.com/ecp/`) to open an Edge InPrivate window and navigate to +++https://outlook.office365.com/ecp/+++ and log in using +++@lab.CloudCredential(81).Username+++ and the password +++@lab.CloudCredential(81).Password+++.  

1. [] Ensure you are under **mail flow** > **rules**, then click on the **plus icon** and click **Create a new rule...**

	![5mfzbjt1.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/5mfzbjt1.jpg)
1. [] In the new rule window, for **Name** type +++Sensitive Data Encrypt Only+++.
1. [] Under **\*Apply this rule if...**, in the drop-down, click on **The recipient is located...**.
1. [] In the select recipient location dialog, in the drop-down, click **Outside the organization**, and click **OK**.

	![x2cj3zor.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/x2cj3zor.jpg)
1. [] Next, click on **More options...** to display th option to add additional conditions.

	![rpqtrf8m.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/rpqtrf8m.jpg)
1. [] Click on **add condition**.

	![mjcrysfj.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/mjcrysfj.jpg)
1. [] Click the **Select one** drop-down and hover over **The message...**, and click on **contains any of these types of sensitive information**.

	![ezuengms.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/ezuengms.jpg)
	![kq8wxegt.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/kq8wxegt.jpg)
1. [] In the Contains any of these sensitive information types dialog, click the **plus sign**.

	![53f6tfbi.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/53f6tfbi.jpg)
1. [] In the Sensitive information types window, scroll down and click on **Credit Card Number**, then click **Add** and **OK**.

	![dgmsayk6.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/dgmsayk6.jpg)
1. [] In the Contains any of these sensitive information types dialog, click **OK**.

	![dihs4zqr.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/dihs4zqr.jpg)
1. [] In the new rule window, under \*Do the following..., in the Select one drop-down, hover over **Modify the message security...** and click on **Apply Office 365 Message Encryption and rights protection**.

	![cu1bgeho.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/cu1bgeho.jpg)
	![rwo2scwt.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/rwo2scwt.jpg)
1. [] In the select RMS template dialog, in the RMS template drop-down, click on **Encrypt** and click **OK**.

	![c8r08bh7.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/c8r08bh7.jpg)
1. [] Review the settings in the new rule window and click **Save**.

	![wwlsz0p2.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/wwlsz0p2.jpg)
	> [!HINT] Next, we need to capture the **Label ID** for the **Confidential \ Contoso Internal** label. 

1. [] Switch to the Azure Portal and under **classifications** click on Labels, then expand **Confidential** and click on **Contoso Internal**.

	![w2w5c7xc.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/w2w5c7xc.jpg)

	> [!HINT] If you closed the azure portal, @[Click here](`cmd.exe/c start shell:AppsFolder\Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge -private https://portal.azure.com`) to open an Edge InPrivate window and navigate to +++https://portal.azure.com+++.

1. [] In the Label: Contoso Internal blade, scroll down to the Label ID and **copy** the value.

	![lypurcn5.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/lypurcn5.jpg)

	> [!ALERT] Make sure that there are no spaces before or after the Label ID as this will cause the mail flow rule to be ineffective.

1. [] Return the rules section of the Exchange admin center, click on the **plus icon** and click **Create a new rule...**

	![5mfzbjt1.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/5mfzbjt1.jpg)
1. [] In the new rule window, for **Name** type +++Block Contoso Internal to External Recipient+++.
1. [] Under **\*Apply this rule if...**, in the drop-down, click on **The recipient is located...**.
1. [] In the select recipient location dialog, in the drop-down, click **Outside the organization**, and click **OK**.

	![on6fbr0d.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/on6fbr0d.jpg)
1. [] Next, click on **More options...** to display th option to add additional conditions.

	![rpqtrf8m.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/rpqtrf8m.jpg)
1. [] Click on **add condition**.

	![cqlps27h.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/cqlps27h.jpg)
1. [] Click the **Select one** drop-down and hover over **A message header...**, and click on **includes any of these words**.

	![zus8h1mn.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/zus8h1mn.jpg)
1. [] Click on **\*Enter text...**, and in the specify header name dialog, type +++msip_labels+++ then click **OK**.

	![jrpy4k02.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/jrpy4k02.jpg)
1. [] Next, click on **\*Enter words...**, and in the specify words or phrases dialog, type +++MSIP_LABEL_+++, **paste the Label ID value** for the Confidential \ Contoso Internal label, then type +++_enabled\=True;+++. Next, click the **plus sign**, and then click **OK**.

	![temiq3e1.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/temiq3e1.jpg)
1. [] In the new rule window, under \*Do the following..., in the Select one drop-down, hover over **Block the message...**, and click **reject the message and include an explanation**.

	![04mlyfs3.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/04mlyfs3.jpg)
	![akeykn8a.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/akeykn8a.jpg)

1. [] In the **specify rejection reason**, type +++Contoso Internal messages cannot be sent to external recipients.+++ and click **OK**.

	![4odbewl3.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/4odbewl3.jpg)

1. [] Review the rule and make sure it looks similar to the picture below and click **Save**.

	![lgg2r4se.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/lgg2r4se.jpg)

===

# Demonstrating Exchange Online Mail Flow Rules
[🔙](#azure-information-protection)

In this task, we will send emails to demonstrate the results of the Exchange Online mail flow rules we configured in the previous task.  This will demonstrate some ways to protect your sensitive data and ensure a positive user experience with the product.

1. [] Switch to @lab.VirtualMachine(Client03).SelectLink.
1. [] In Microsoft Outlook, click on the **New email** button.

	^IMAGE[Open Screenshot](6wan9me1.jpg)

1. [] Send an email to Alan, Amy, and yourself (+++AlanS;AmyA;@lab.User.Email+++).  For the **Subject**, type +++Test Credit Card Email+++ and for the **Body**, type +++My AMEX card number is 344047014854133. The expiration date is 09/28, and the CVV is 4368+++, then click **Send**.

	> [!KNOWLEDGE] Notice that there is a policy tip that has popped up to inform you that there is a credit card number in the email and it is being shared outside the organization.  This type of policy tip can be defined with the Office 365 Security and Compliance center and was pre-staged in the demo tenants we are using.  

1. [] Switch to @lab.VirtualMachine(Client01).SelectLink and review the received email.

	![pidqfaa1.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/pidqfaa1.jpg)

	> [!Knowledge] Note that there is no encryption applied to the message.  That is because we set up the rule to only apply to external recipients.  If you were to leave that condition out of the mail flow rule, internal recipients would also receive an encrypted copy of the message.  The image below shows the encrypted message that was received externally.
	>
	>![c5foyeji.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/c5foyeji.jpg)
	>
	>Below is another view of the same message received in Outlook Mobile on an iOS device.
	>
	>![599ljwfy.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/599ljwfy.jpg)

	>[!NOTE] Note that you have received a message from your DLP policy stating that the email was not sent to the external recipient because it contained a credit card number.

1. [] On Client 1, @[Click here](`cmd.exe/c start shell:AppsFolder\Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge -private https://protection.office.com`) to open an Edge InPrivate window to +++https://protection.office.com+++.
1. [] In the Security and Compliance Center, expand **Data loss prevention** and click on **Policy**.  Then, in the Policy blade, click on the **Default Office 365 DLP Policy**.
	
	![a2m7ryn4.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/a2m7ryn4.jpg)
1. [] In the Default Office 365 DLP Policy blade, next to Policy settings, click **Edit**.

	![jsdej5i4.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/jsdej5i4.jpg)
1. [] In the Editing policy settings blade, disable the switch next to **Items containing 1-9 credit card numbers shared externally** and click **Save**.

![5y5gg696.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/5y5gg696.jpg)
1. [] Return to @lab.VirtualMachine(Client03).SelectLink.
1. [] In Microsoft Outlook, click on the **New email** button.

	^IMAGE[Open Screenshot](6wan9me1.jpg)

1. [] Send an new email to Alan, Amy, and yourself (+++AlanS;AmyA;@lab.User.Email+++).  For the **Subject**, type +++Test Credit Card Email 2+++ and for the **Body**, type +++My AMEX card number is 344047014854133. The expiration date is 09/28, and the CVV is 4368+++, then click **Send**.
1. [] Wait a few moments for the DLP policy to recognize the credit card number and external email and then in the DLP Policy Tip, click **override**.

	![aezwvoir.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/aezwvoir.jpg)
1. [] In the Override dialog, type +++Lab Demo+++ and click **Override**

	![7o8406n7.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/7o8406n7.jpg)
	>[!Knowledge] Notice that you do not receive the error messag this time.  Log into your personal email and you will see that the email has been encrypted in transit by the Exchange Online Mail Flow Rule defined in the previous exercise.
1. [] Next, in Microsoft Outlook, click on the **New email** button.

	^IMAGE[Open Screenshot](6wan9me1.jpg)
1. [] Send an email to Alan, Amy, and yourself (+++AlanS;AmyA;@lab.User.Email+++).  For the **Subject** and **Body** type +++Another Test Contoso Internal Email+++.

	^IMAGE[Open Screenshot](d476fmpg.jpg)

1. [] In the Sensitivity Toolbar, click on the **pencil** icon to change the Sensitivity label.

	^IMAGE[Open Screenshot](901v6vpa.jpg)

1. [] Click on **Confidential** and then **Contoso Internal** and click **Send**.

	^IMAGE[Open Screenshot](yhokhtkv.jpg)
1. [] In about a minute, you should receive an **Undeliverable** message from Exchange with the users that the message did not reach and the message you defined in the previous task.

	![kgjvy7ul.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/kgjvy7ul.jpg)

> [!HINT] There are many other use cases for Exchange Online mail flow rules but this should give you a quick view into what is possible and how easy it is to improve the security of your sensitive data through the use of Exchange Online mail flow rules and Azure Information Protection.

===

# Exercise 5: SharePoint IRM Configuration
[🔙](#azure-information-protection)

In this exercise, you will configure SharePoint Online Information Rights Management (IRM) and configure a document library with an IRM policy to protect documents that are downloaded from that library.

===
# Enable Information Rights Management in SharePoint Online
[🔙](#azure-information-protection)
![52a7iwuj.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/52a7iwuj.jpg)
In this task, we will enable Information Rights Management in SharePoint Online.

1. [] Switch to **@lab.VirtualMachine(Client03).SelectLink**.

1. [] @[Click here](`cmd.exe/c start shell:AppsFolder\Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge -private https://admin.microsoft.com/AdminPortal/Home#/homepage`) to launch an Edge InPrivate session to +++https://admin.microsoft.com/AdminPortal/Home#/homepage+++.
 
1. [] If needed, log in using +++@lab.CloudCredential(81).Username+++ and the password +++@lab.CloudCredential(81).Password+++.
 
1. [] Hover over the **Admin centers** section of the bar on the left and choose **SharePoint**.

	![r5a21prc.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/r5a21prc.jpg)
 
1. [] In the SharePoint admin center click on **settings**.

1. [] Scroll down to the Information Rights Management (IRM) section and select the option button for **Use the IRM service specified in your configuration**.
 
1. [] Click the **Refresh IRM Settings** button.

	![1qv8p13n.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/1qv8p13n.jpg)

	>[!HINT] After the browser refreshes, you can scroll down to the same section and you will see a message stating **We successfully refreshed your setings.**
	>
	>![daeglgk9.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/daeglgk9.jpg)
 
1. [] Keep the browser open and go to the next task.
 
===

# Site Creation and Information Rights Management Integration
[🔙](#azure-information-protection)
![52a7iwuj.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/52a7iwuj.jpg)
In this task, we will create a new SharePoint site and enable Information Rights Management in a document library.

1. [] In the upper left-hand corner of the page, click on the **app launcher** and click on **SharePoint** in the list.

	![ahiylfbv.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/ahiylfbv.jpg)

	![s5wj8fpe.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/s5wj8fpe.jpg)

1. [] Dismiss any introductory screens and, at the top of the page, click **+Create site**.

	![7v8wctu2.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/7v8wctu2.jpg)
 
1. [] On the Create a site page, click **Team site**.

	^IMAGE[Open Screenshot](406ah98f.jpg)
 
1. [] On the next page, type +++IRM Demo+++ for **Site name** and for the **Site description**, type +++This is a team site for demonstrating SharePoint IRM capabilities+++ and set the **Privacy settings** to **Public - anyone in the organization can access the site** and click **Next**.

	^IMAGE[Open Screenshot](ug4tg8cl.jpg)

1. [] On the Add group members page, click **Finish**.
1. [] In the newly created site, on the left navigation bar, click **Documents**.

	^IMAGE[Open Screenshot](yh071obk.jpg)
 
1. [] In the upper right-hand corner, click the **Settings icon** and click **Library settings**.

	![1qo31rp6.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/1qo31rp6.jpg)
 
1. [] On the Documents > Settings page, under **Permissions and Management**, click **Information Rights Management**.

	![ie2rmsk2.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/ie2rmsk2.jpg)
 
1. [] On the Settings > Information Rights Management Settings page, check the box next to Restrict permissions on this library on download and under **Create a permission policy title** type +++Contoso IRM Policy+++, and under **Add a permission policy description** type +++This content contained within this file is for use by Contoso Corporation employees only.+++
 
	^IMAGE[Open Screenshot](m9v7v7ln.jpg)
1. [] Next, click on **SHOW OPTIONS** below the policy description and in the **Set additional IRM library settings** section, check the boxes next to **Do not allow users to upload documents that do not support IRM** and **Prevent opening documents in the browser for this Document Library**.

	![0m2qqtqn.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/0m2qqtqn.jpg)
	>[!KNOWLEDGE] These setting prevent the upload of documents that cannot be protected using Information Rights Managment (Azure RMS) and forces protected documents to be opened in the appropriate application rather than rendering in the SharePoint Online Viewer.
 
1. [] Next, under the **Configure document access rights** section, check the box next to **Allow viewers to run script and screen reader to function on downloaded documents**.

	![72fkz2ds.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/72fkz2ds.jpg)
	>[!HINT] Although this setting may reduce the security of the document, this is typically provided for accessibility purposes.
1. [] Finally, in the **Configure document access rights** section, check the box next to  **Users must verify their credentials using this interval (days)** and type +++7+++ in the text box.

	![tt1quq3f.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/tt1quq3f.jpg)
1. [] At the bottom of the page, click **OK** to complete the configuration of the protected document library.
1. [] On the Documents > Settings page, in the left-hand navigation pane, click on **Documents** to return to the document library. section.
 
1. [] Leave the browser open and continue to the next task.
 
===

# Uploading Content to the Document Library
[🔙](#azure-information-protection)
![52a7iwuj.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/52a7iwuj.jpg)
Create an unprotected Word document, label it as Internal, and upload it to the document library. 

1. [] @[Click here](`"C:\\Program Files (x86)\\Microsoft Office\\root\\Office16\\WINWORD.EXE"`) to launch **Microsoft Word**.
1. [] Create a new **Blank document**.

	>[!NOTE] Notice that by default the document is labeled as the unprotected classification **General**.
 
1. [] In the Document, type +++This is a test document+++.
 
1. [] **Save** the document and **close Microsoft Word**.
1. [] Return to the IRM Demo protected document library and click on **Upload > Files**.

	![m95ixvv1.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/m95ixvv1.jpg)
1. [] Navigate to the location where you saved the document, select it and click **Open** to upload the file.
 
	>[!NOTE] Note that despite this document being labeled, the Sensitivity is not listed.
 
1. [] To resolve this, on the right-hand side of the document library, click on the **+ Add column** header and click on **More...**.

	![y8h1vf7o.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/y8h1vf7o.jpg)
1. [] In the Settings > Create Column page, under **Column name:**, type +++Sensitivity+++.  Verify that **The type of information in this column is:** is set to **Single line of text**, and click **OK**. 

	![66hzke2b.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/66hzke2b.jpg)
1. [] In the document library, click on the **Show actions** button to the right of the uploaded document and click **Delete**.

	![gt7sjulo.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/gt7sjulo.jpg)
	>[!Note] This is only necessary to expedite the appearance of the Sensitivity metadata.  In production, this would be unnecessary.
1. [] Re-upload the document and you will see that the Sensitivity column is populated.

	![0yr96t56.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/0yr96t56.jpg)
1. [] Next, minimize the browser window and right-click on the desktop. Hover over **New >** and click on **Microsoft Access Database**. Name the database +++BadFile+++.

	![e3nxt4a2.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/e3nxt4a2.jpg)
1. [] Return to the document library and attempt to upload the file.

	>[!KNOWLEDGE] Notice that you are unable to upload the file because it cannot be protected.
	>	
	>![432hu3pi.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/432hu3pi.jpg)
===

# SharePoint IRM Functionality
[🔙](#azure-information-protection)
![52a7iwuj.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/52a7iwuj.jpg)
Files that are uploaded to a SharePoint IRM protected document library are protected upon download based on the user's access rights to the document library.  In this task, we will share a document with Amy Alberts and review the access rights provided.

1. [] Select the uploaded document and click **Share** in the action bar.

	![1u2jsod7.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/1u2jsod7.jpg)
1. [] In the Send Link dialog, type +++AmyA+++ and click on **Amy Alberts** then **Send**.

	![j6w1v4z9.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/j6w1v4z9.jpg)
1. [] Switch to @lab.VirtualMachine(Client02).SelectLink.
1. [] Open Outlook and click on the email from CIE Administrator, then click on the **Open** link.

	^IMAGE[Open Screenshot](v39ez284.jpg)
1. [] This will launch the IRM Demo document library.  Click on the document to open it in Microsoft Word.

	![xmv9dmvk.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/xmv9dmvk.jpg)
1. [] After the document opens, you will be able to observer that it is protected.  Click on the View Permissions button to review the restrictions set on the document.

	![4uya6mro.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/4uya6mro.jpg)
	>[!NOTE] These permissions are based on the level of access that they user has to the document library.  In a production environment most users would likely have less rights than shown in this example.
	
===
 
# Exercise 6: Classification, Labeling, and Protection with the Azure Information Protection Scanner
[🔙](#azure-information-protection)

The Azure Information Protection scanner allows you to  classify and protect sensitive information stored in on-premises CIFS file shares and SharePoint sites.  

In this exercise, you will use the information gathered in Exercise 1 to map sensitive data types discovered to automatic classification rules.  After that, we will run the AIP Scanner in enforce mode to classify and protect the identified sensitive data.

===


# Configuring Automatic Conditions
[🔙](#azure-information-protection)
![52a7iwuj.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/52a7iwuj.jpg)
Now that we know what types of sensitive data we need to protect, we will configure some automatic conditions (rules) that the scanner can use to classify and protect content.

1. [] Switch back to @lab.VirtualMachine(Scanner01).SelectLink and open the browser that is logged into the Azure Portal.

1. [] Under **classifications** on the left, click **Labels** then expand **Confidential**, and click on **Contoso Internal**.

	^IMAGE[Open Screenshot](jyw5vrit.jpg)
1. [] In the Label: Contoso Internal blade, scroll down to the **Configure conditions for automatically applying this label** section, and click on **+ Add a new condition**.

	![cws1ptfd.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/cws1ptfd.jpg)
1. [] In the Condition blade, in the **Select information types** search box, type +++SSN+++ and check the box next to the 3 **Social Security Number** entries.

	^IMAGE[Open Screenshot](a6dfnuyz.jpg)
1. [] Click **Save** in the Condition blade and **OK** to the Save settings prompt.

	^IMAGE[Open Screenshot](41o5ql2y.jpg)
1. [] In the Label : Contoso Internal blade, under **Select how this label is applied: automatically or recommended to user**, click **Automatic**.

	^IMAGE[Open Screenshot](1ifaer4l.jpg)

1. [] Click **Save** in the Label: Contoso Internal blade and **OK** to the Save settings prompt.

	^IMAGE[Open Screenshot](rimezmh1.jpg)
1. [] Press the **X** in the upper right-hand corner to close the Label: Contoso Internal blade.

===

# Enforcing Configured Rules
[🔙](#azure-information-protection)
![52a7iwuj.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/52a7iwuj.jpg)
In this task, we will se the AIP scanner to enforce the conditions we set up in the previous task and have it rerun on all files using the Start-AIPScan -Reset command.

1. [] Run the commands below to run an enforced scan using defined policy.

    ```
	Set-AIPScannerConfiguration -Enforce On -DiscoverInformationTypes PolicyOnly
	```
	```
	Start-AIPScan -Reset
    ```

	> [!HINT] Note that this time we used the DiscoverInformationTypes -PolicyOnly switch before starting the scan. This will have the scanner only evaluate the conditions we have explicitly defined in conditions.  This increases the effeciency of the scanner and thus is much faster.  After reviewing the event log we will see the result of the enforced scan.
	>
	>![k3rox8ew.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/k3rox8ew.jpg)
	>
	>If we switch back to @lab.VirtualMachine(Client03).SelectLink and look in the reports directory we opened previously, you will notice that the old scan reports are zipped in the directory and only the most recent results aare showing.  
	>
	>![s8mn092f.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/s8mn092f.jpg)
	>
	>Also, the DetailedReport.csv now shows the files that were protected.
	>
	>
	>![6waou5x3.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/6waou5x3.jpg)
	>
	>^IMAGE[Open Fullscreen](6waou5x3.jpg)

===

# Reviewing Protected Documents
[🔙](#azure-information-protection)

Now that we have Classified and Protected documents using the scanner, we can review the documents we looked at previously to see their change in status.

1. [] Switch to @lab.VirtualMachine(Client01).SelectLink.
 
2. [] @[Click here](`cmd.exe/c start shell:AppsFolder\Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge -private http://Scanner01/documents`) to navigate to ***http://Scanner01/documents***. Provide the credentials +++LabUser+++ and +++Pa$$w0rd+++ if prompted.
 
	^IMAGE[Open Screenshot](hipavcx6.jpg)
3. [] Open one of the Contoso Purchasing Permissions documents or Run For The Cure spreadsheets.
 
 	
	
	> [!NOTE] Observe that the same document is now classified as Confidential \ Contoso Internal. You can also see these same documents on a file share at \\Scanner01\documents in their new protected state.
	>
	>![s1okfpwu.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/s1okfpwu.jpg)


===

# CONGRATULATIONS!
[🔙](#azure-information-protection)

![kt7yaogd.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/kt7yaogd.jpg)


===
# Windows Defender Advanced Threat Protection
[🔙](#introduction)

1. [] logon to: https://securitycenter.windows.com/
1. [] add your credentials [Note to Kevin: need to add username and password]
1. [] You may need to setup  your Windows Defender ATP tenant for the first time.  see "Access Windows Defender Security Center" section here: https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-atp/licensing-windows-defender-advanced-threat-protection
1. [] You may also need to onboard machine to WDATP service.  see details here: https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-atp/onboard-configure-windows-defender-advanced-threat-protection
1. [] run attack simulation #4 "Automated investigation (fileless attack)" on your selected victim client.  Details can be found here: https://securitycenter.windows.com/tutorials.  Please note that you will need to use your WDATP access credentials to access this link [Note to Kevin:  add username and password if possible]

![52a7iwuj.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/52a7iwuj.jpg)
===
# Azure Advanced Threat Protection
[🔙](#introduction)

### Please see externally provided instructions for this lab.

![52a7iwuj.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/52a7iwuj.jpg)
===
# Azure Security Center
[🔙](#introduction)

### Please see externally provided instructions for this lab.

===
# Azure Active Directory
[🔙](#introduction)

### Please see externally provided instructions for this lab.

![52a7iwuj.jpg](https://github.com/kemckinnmsft/AIPLAB/blob/master/Content/52a7iwuj.jpg)


