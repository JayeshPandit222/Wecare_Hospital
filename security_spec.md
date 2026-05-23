# Security Specification: WeCare Hospital Scheduler

## Data Invariants
1. **Identity Isolation**: A user profile (`/users/{userId}`) can only be read, created, or updated by the user whose authenticated `request.auth.uid` matches the `userId` in the path. No other user can view or edit this profile.
2. **Strict Structure**: User data, Appointments, and Saved Doctors ("Lookings") are hosted in path-isolated subcollections under `/users/{userId}/...`. This guarantees that user access control cascades logically.
3. **No Update Cascading or Side-Channels**: Users cannot spoof UIDs inside the payload. The `userId` of any appointment or looking payload must match the authenticating user's ID.
4. **Finite Capacity**: String sizes and key structures are strictly validated to block "Denial of Wallet" resource floods.

---

## The "Dirty Dozen" Malicious Payloads
The following payloads are explicitly designed to test our zero-trust defenses. Security rules must block all of them with a `PERMISSION_DENIED` response.

### 1. Identity Spoofing (Spoofing User Profile)
*   **Path**: `/users/legit-user-abc`
*   **User**: `mallory-attacker-xyz`
*   **Payload**: `{"userId": "mallory-attacker-xyz", "name": "Attacker", "email": "attacker@gmail.com"}`
*   **Vulnerability Target**: Modification of other clients' master profiles.

### 2. Identity Spoofing (Injecting foreign uid within payload)
*   **Path**: `/users/attacker-xyz/appointments/apt-1`
*   **User**: `attacker-xyz`
*   **Payload**: `{"userId": "legit-user-abc", "doctorId": "dr-adrian", "patientName": "Legit User" ...}`
*   **Vulnerability Target**: Writing items on behalf of other verified accounts.

### 3. Ghost Field / Shadow Update Attack
*   **Path**: `/users/user-abc`
*   **User**: `user-abc`
*   **Payload**: `{"userId": "user-abc", "name": "User", "email": "user@gmail.com", "isAdmin": true}`
*   **Vulnerability Target**: Elevating client permissions using unchecked secondary attributes.

### 4. Path variable ID Poisoning (Long Strings)
*   **Path**: `/users/user-abc/appointments/VERY_LONG_ID_WITH_1000_CHARACTERS_THAT_SHOULD_BE_BLOCKED_TO_PREVENT_DATABASE_CORRUPTION_OR_EXCESSIVE_BILLING_FOR_STORAGE_AND_INDEXES_abc`
*   **User**: `user-abc`
*   **Payload**: `{"id": "short-id", "userId": "user-abc", ...}`
*   **Vulnerability Target**: Resource exhaustion vectors & NoSQL structure poisoning.

### 5. Type Manipulation Check
*   **Path**: `/users/user-abc/appointments/apt-1`
*   **User**: `user-abc`
*   **Payload**: `{"doctorId": 12345, "doctorName": ["Dr. Adrian"], "patientName": true, ...}`
*   **Vulnerability Target**: Bypassing client UI inputs to break downstream servers/parsing models.

### 6. Value Poisoning (Invalid Enums)
*   **Path**: `/users/user-abc/appointments/apt-2`
*   **User**: `user-abc`
*   **Payload**: `{"status": "VIP_PREMIUM_METRIC", ...}`
*   **Vulnerability Target**: Forcing states not permitted by standard clinical guidelines.

### 7. Terminal State Lock Tampering
*   **Path**: `/users/user-abc/appointments/apt-3`
*   **User**: `user-abc` (Original Creator)
*   **Payload**: Changing `status` from `"Completed"` back to `"Scheduled"` or direct modifications of already completed consultation histories.
*   **Vulnerability Target**: Rewriting medical timelines or clinical appointment status lists.

### 8. System-Only Field Escalation
*   **Path**: `/users/user-abc/appointments/apt-4`
*   **User**: `user-abc` (Original Creator)
*   **Payload**: Modifying AI-generated metadata or doctor admin feedback remarks.
*   **Vulnerability Target**: Unauthorized edits to clinically governed properties.

### 9. Query Scraping List Leak
*   **Query**: Reading all profiles `/users` without limiting to specific authenticated paths.
*   **User**: `anonymous` or `attacker-xyz`
*   **Vulnerability Target**: Bulk user information harvesting.

### 10. Temporal Spoofing (Impersonating server time)
*   **Path**: `/users/user-abc/appointments/apt-5`
*   **User**: `user-abc`
*   **Payload**: `{"createdAt": "2020-01-01T00:00:00Z", ...}` (Backdated custom entry)
*   **Vulnerability Target**: Messing up logs and audit trailing.

### 11. Immutability Violation (Modifying Immutable Properties)
*   **Path**: `/users/user-abc/appointments/apt-1`
*   **User**: `user-abc`
*   **Payload**: Attempting to alter `doctorId` or `createdAt` of an active booked slot.
*   **Vulnerability Target**: State integrity issues.

### 12. PII Blanket Access Theft
*   **Request**: `get` on `/users/victim-123`
*   **User**: `stalker-456`
*   **Vulnerability Target**: Breach of user contact privacy and details.

---

## Test Runner Setup

To test these constraints locally, create `firestore.rules.test.ts`:

```typescript
import { assertFails, assertSucceeds, initializeTestEnvironment } from "@firebase/rules-unit-testing";

// Standard TDD rules test suite covering target payloads.
describe("WeCare Firebase Security Specifications Test", () => {
    it("fails malicious user spoof profile updates", async () => {
        // Assert Mallory cannot create a profile at /users/legit-user-abc
    });
});
```
