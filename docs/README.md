# SecureShare Documentation

This documentation covers client workflows, application architecture, the Entra ID access model, operating procedures, and troubleshooting. Client guides describe the current application; configurable defaults should be checked against your deployment.

## Client guides and diagrams

- [Upload and share files](SecureShare-Client-Guide.md): sign in, upload, copy links, download, and revoke access.
- [Admin portal guide](SecureShare-Admin-Guide.md): review activity, interpret results, filter reports, and export CSV files.
- [Application diagram](SecureShare-Application-Diagram.md): architecture and file-sharing workflow, with editable Mermaid diagrams.

## Technical and operator documents

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
