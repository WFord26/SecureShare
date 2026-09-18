# SecureShare Documentation

This documentation describes the deployed SecureShare service, its Entra ID access model, operating procedures, and common troubleshooting steps.

## Documents

- [As-built document](SecureShare-As-Built.md)
- [SOP: Add users through an Entra security group](SOP-Add-Users.md)
- [SOP: Add administrators through an Entra security group](SOP-Add-Administrators.md)
- [Troubleshooting guide](SecureShare-Troubleshooting.md)

## Scope and ownership

The procedures assume:

- Azure App Service hosts the Node.js application.
- Microsoft Entra ID controls sign-in and application role assignment.
- Azure Blob Storage stores uploaded files.
- Microsoft Defender for Storage scans files on upload.
- Azure Table Storage stores the upload and download audit records.
- The operator has the required Azure subscription and Entra administration permissions.

Do not commit `infra/deploy.env`. It contains generated application secrets and is intentionally excluded from source control.
