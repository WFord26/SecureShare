# SOP: Add Administrators to sg-SecureShareAdmins

## Purpose

Grant a person access to SecureShare audit reports and CSV exports by adding them to the `sg-SecureShareAdmins` Entra security group.

## Required access

- Microsoft Entra administrator access to the SecureShare enterprise application.
- Approval from the SecureShare service owner or security owner.
- Permission to manage membership of `sg-SecureShareAdmins`.

## Procedure

1. Confirm the requestor, business justification, approver, and expected duration of administrative access.
2. Open **Microsoft Entra admin center** -> **Identity** -> **Applications** -> **Enterprise applications**.
3. Open the SecureShare enterprise application.
4. Open **Users and groups** and verify that `sg-SecureShareAdmins` is assigned the `Audit.Read` application role.
5. Add the user to `sg-SecureShareAdmins`. Do not add the user to an alternative administrator group or grant administrator access through an individual application-role assignment.
6. Confirm the user is a direct member of `sg-SecureShareAdmins`. Nested group membership is not included by the deployment script.
7. Record the change in the access-management ticket, including the user, group, role, approver, and timestamp.
8. Ask the user to sign out of SecureShare and sign in again.

## Validation

1. Confirm the user appears as a member of `sg-SecureShareAdmins`.
2. Sign in as the new administrator.
3. Open `/admin`.
4. Confirm the report loads and includes expected upload/download records.
5. Open one file's download details.
6. Confirm both CSV export links work.
7. Confirm a standard uploader without `Audit.Read` receives a not-authorized response from `/admin`.

## Security requirements

- Keep the administrator group small and reviewed regularly.
- Treat CSV exports as sensitive because they can contain identities, IP addresses, user agents, timestamps, and file metadata.
- Remove access promptly when the user's role changes or employment ends.
- Review administrator membership at least quarterly or according to the organization's access-review policy.
