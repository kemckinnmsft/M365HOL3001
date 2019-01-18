1. [] Switch to @lab.VirtualMachine(VictimPC).SelectLink and log in with the password +++@lab.VirtualMachine(VictimPC).Password+++.

1. [] Switch to @lab.VirtualMachine(AdminPC).SelectLink and log in with the password +++@lab.VirtualMachine(AdminPC).Password+++.

1. [] Switch to @lab.VirtualMachine(ContosoDC).SelectLink and log in with the password +++@lab.VirtualMachine(ContosoDC).Password+++.

1. [] Switch to @lab.VirtualMachine(Scanner01).SelectLink and log in with the password +++@lab.VirtualMachine(Scanner01).Password+++.

1. [] Switch to @lab.VirtualMachine(Client01).SelectLink and log in with the password +++@lab.VirtualMachine(Client01).Password+++.

1. [] Switch to @lab.VirtualMachine(Client02).SelectLink and log in with the password +++@lab.VirtualMachine(Client02).Password+++.

1. [] Switch to @lab.VirtualMachine(Client03).SelectLink and log in with the password +++@lab.VirtualMachine(Client03).Password+++.

1. [] Log in using the credentials below:

	+++@lab.CloudCredential(134).Username+++

	+++@lab.CloudCredential(134).Password+++

    $tenantfqdn = @lab.cloudcredential(134).TenantName
    $tenant = $tenantfqdn.Split('.')

!IMAGE[activity.png](\Media\activity.png)

https://labondemand.com/AuthenticatedLaunch/48390?providerId=4 



Move new group creation steps from delegation MCAS page


Install Adobe and MIP plugin 

Make modification to registry for PDF

Add PDF instructions to HOL3000/M365HOL

delete change log and recent files on scanner01
username,displayname,password
AdamS,Adam Smith,pass@word1
AIPScanner,AIPScanner,Somepass1
alicea,Alice Anderson,pass@word1
evang,Evan Green,pass@word1
nuckc,Nuck Chorris,NinjaCat123
bobh,Bob Helpdesk,Password123!@#
McasAdminUS,MCAS AdminUS,pass@word1