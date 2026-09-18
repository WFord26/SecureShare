# SOP: Add Users to sg-SecureShare

## Purpose

Grant a person permission to sign in and upload files by adding them to the `sg-SecureShare` Entra security group, without granting access to the audit console.

## Required access

- Microsoft Entra administrator access to the SecureShare enterprise application.
- Permission to manage membership of `sg-SecureShare`.

## Procedure

1. Confirm the requestor, business need, manager approval, and required end date if access is temporary.
2. Open **Microsoft Entra admin center** -> **Identity** -> **Applications** -> **Enterprise applications**.
3. Open the SecureShare enterprise application.
4. Open **Users and groups** and verify that `sg-SecureShare` is assigned the `Files.Upload` application role.
5. Add the user to `sg-SecureShare`. Do not assign `Audit.Read` for a standard uploader.
6. Confirm the user is a direct member of `sg-SecureShare`. Nested group membership is not included by the deployment script.
7. Record the change in the access-management ticket, including the user, group, role, approver, and timestamp.
8. Ask the user to sign out of existing SecureShare sessions and sign in again. Role changes are read at sign-in.

## Validation

1. Confirm the user appears as a member of `sg-SecureShare`.
2. Sign in as the new user.
3. Confirm the upload page is available.
4. Upload a non-sensitive test file.
5. Confirm the generated link opens in a private browser window after the scan is complete.
6. Confirm `/admin` is not available unless the user is also a member of `sg-SecureShareAdmins`.

## Removal and review

Remove the user from `sg-SecureShare` when access is no longer required. Removals must be performed through the approved Entra identity-management process.

## Common failure

If Entra reports that `sg-SecureShare` cannot be assigned to the app role, verify the group's existing `Files.Upload` assignment and escalate to the SecureShare service owner. Do not work around this by granting broad tenant-wide access or using a different group.
