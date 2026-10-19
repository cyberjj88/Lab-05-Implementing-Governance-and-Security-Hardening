# Lab 05: Implementing Governance and Security Hardening

**Author:** Jair Smith
**Series:** Azure Cloud Security Series
**Lab Number:** 05 of ongoing curriculum
**Difficulty:** Beginner
**Estimated Time:** 60-75 Minutes
**Framework:** NIST Cybersecurity Framework (CSF)
**Prerequisites:** Active Azure subscription, Completed Week 5 Video Modules

Full Lab:
https://www.loom.com/share/bbc7f2c91e4d4951a58ae31523b91936


---

## Overview

Cloud governance answers three questions: Who is allowed to do what? What configurations are allowed to be deployed? How much are we allowed to spend, and who gets notified when we approach the limit?

This lab gives you hands-on experience with all three. By the end you will have restricted a junior employee to view-only access using RBAC, enforced a rule that prevents anyone from deploying expensive server sizes using Azure Policy, and set up a spending alert using Cost Management that notifies you before the bill gets out of hand.

**How to explain this in a job interview:** "Governance is the process of making sure the right people have the right access, the right configurations are deployed, and the organisation knows when something is drifting outside acceptable boundaries before it becomes an incident."

---

## NIST Cybersecurity Framework Alignment

Every phase of this lab maps directly to one of the five NIST CSF functions. You do not need to memorise the entire framework. What matters is that you can explain how the work you do as a cloud engineer fits into it.

| NIST Function | Plain English Meaning | Where It Appears in This Lab |
|---------------|-----------------------|------------------------------|
| **Identify**  | Know what you have, who has access to it, and what the risks are. | Creating a user in Microsoft Entra ID and understanding who that user is before assigning permissions. You cannot protect what you have not identified. |
| **Protect**   | Put controls in place to limit what can go wrong. | The Reader role assignment (RBAC) and the VM size policy (Azure Policy) are both Protect controls. They limit what damage any person or misconfiguration can do. |
| **Detect**    | Know when something abnormal is happening. | The budget alert is a Detect control. A sudden spike in cloud spend can indicate a misconfigured resource, a forgotten deployment, or even a compromised account spinning up crypto miners. |
| **Respond**   | Have a plan for when something goes wrong. | Receiving the budget alert email and knowing you need to investigate is the beginning of a Respond process. In a real organisation this would trigger an incident response workflow. |
| **Recover**   | Restore normal operations after an incident. | The cleanup phase (deleting the test user and resource group) is Recover thinking: cleaning up after yourself so the environment is back to a known good state. |

> NIST alignment is not a box you tick once. It is a continuous process. Every resource you deploy, every access you grant, and every policy you create either strengthens or weakens your organisation's NIST posture.

---

## Architecture Overview

The diagram below shows how the three governance controls interact. The admin creates the user, assigns the role, and applies the policy. The Junior Developer can only view resources and is blocked when attempting to create anything. The budget alert runs independently at the resource group level and fires automatically when thresholds are crossed.

```
Azure Tenant
+------------------------------------------------------------------------+
|  Microsoft Entra ID                                                    |
|  +---------------------------+   +----------------------------+        |
|  |  Admin Account            |   |  Junior Developer (test)   |        |
|  |  (Owner role)             |   |  junior-dev-[yourname]     |        |
|  |                           |   |  Role: Reader (scoped to   |        |
|  |  Creates user             |-->|  rg-lab05-gov-[yourname])  |        |
|  |  Assigns Reader role      |   +----------------------------+        |
|  |  Creates policy           |             |                           |
|  |  Creates budget           |             | Can: view resources       |
|  +---------------------------+             | Cannot: create / modify   |
|                                            |         / delete          |
+--------------------------------------------|--------------------------+
                                             |
                                             v
+------------------------------------------------------------------------+
|  rg-lab05-gov-[yourname]  (Resource Group scope)                      |
|                                                                        |
|  +------------------------------+  +--------------------------------+  |
|  |  RBAC Control                |  |  Azure Policy Control          |  |
|  |  (NIST: Protect)             |  |  (NIST: Protect)               |  |
|  |                              |  |                                |  |
|  |  Reader role assigned to     |  |  Assignment: Restrict-VM-Sizes |  |
|  |  Junior Developer            |  |  Effect: Deny                  |  |
|  |                              |  |  Allowed: B1s, B1ms only       |  |
|  |  Blocks: create, modify,     |  |  Blocks: all other VM sizes    |  |
|  |          delete              |  |  Applies to: everyone,         |  |
|  |  Allows: read only           |  |  including Owner accounts      |  |
|  +------------------------------+  +--------------------------------+  |
|                                                                        |
|  +-------------------------------------------------------------+       |
|  |  Cost Management Budget                                     |       |
|  |  (NIST: Detect)                                             |       |
|  |                                                             |       |
|  |  Monthly-Lab-Budget: $50                                    |       |
|  |  Alert 1: 80% Actual  = $40 spent  --> email fires          |       |
|  |  Alert 2: 100% Forecast             --> email fires early   |       |
|  |                                                             |       |
|  |  Note: Budget does NOT stop spending.                       |       |
|  |        It is a smoke detector, not a sprinkler system.      |       |
|  +-------------------------------------------------------------+       |
+------------------------------------------------------------------------+

How all three controls work together:
  Junior Dev tries to delete DB   --> RBAC blocks it (AuthorizationFailed)
  Engineer deploys 32-core VM     --> Policy blocks it (Validation failed)
  Load balancer left running      --> Budget alert fires at 80% threshold
  Attacker spins up crypto miners --> Policy blocks large VMs + Budget
                                      fires when allowed sizes spike spend
```

---

## Key Concepts: Read Before You Start

### Role-Based Access Control (RBAC)

RBAC is the system Azure uses to control who can do what. Think of it like job titles in a company. A Receptionist can see who is in the building and take messages but cannot access the server room. A System Administrator can access the server room but maybe not sign financial contracts. The title defines the permissions. In Azure, the Role is the title.

| Role Name    | What It Can and Cannot Do | Who It Is For |
|--------------|---------------------------|---------------|
| Owner        | Can do everything including grant access to other people. | A very small number of trusted administrators only. |
| Contributor  | Can create, modify, and delete resources but cannot grant access to others. | Engineers who need to build things but should not control who has access. |
| Reader       | Can view everything but cannot create, modify, or delete anything. | The Junior Developer in this lab. View-only. |
| Custom roles | Exactly the permissions you need, nothing more. | Enterprise environments. Out of scope for this lab but important to know exists. |

> **Principle of least privilege:** Always give someone the minimum access they need to do their job and nothing more. RBAC is how you enforce this in Azure.

> **Scope matters:** In this lab you assign the Reader role scoped to one specific resource group. That means the Junior Developer can view resources inside that group but has no visibility into anything else in the subscription.

### Azure Policy

RBAC controls who can act. Azure Policy controls what configurations are allowed. Even if you trust someone enough to give them Contributor access, you might still want to prevent them from deploying a server that costs $5,000 a month or deploying resources to an unapproved region.

Think of Azure Policy like building codes. A contractor can build whatever the client asks for, but the city has rules that say the building must meet certain safety standards regardless of what the client wants. Azure Policy is the building code for your cloud environment.

| Policy Concept     | What It Means |
|--------------------|---------------|
| Policy definition  | The rule itself. "Only allow these VM sizes" or "All resources must have a CostCenter tag." Azure has hundreds of built-in definitions. You can also write custom ones. |
| Policy assignment  | Applying a definition to a scope. A definition does nothing until it is assigned. |
| Scope              | The boundary the policy applies to. In this lab: your lab resource group only, not the entire subscription. |
| Effect             | What happens when a resource violates the policy. "Deny" blocks the deployment. "Audit" allows it but logs a warning. "Append" automatically adds required settings. This lab uses Deny. |
| Evaluation         | Policy is evaluated at deployment time, before the resource is created. Takes 10-30 minutes to fully propagate after assignment. |

> **Azure Policy applies to everyone, including Admins.** Unlike RBAC (which you can work around if you have Owner rights), a Deny policy blocks even the account that created it. Governance cannot be bypassed by elevating your own permissions.

### Cost Management and Budgets

Cloud spend is one of the most common sources of governance failures. Not because of malicious intent, but because it is very easy to forget a resource is running. A VM left on over a weekend, a load balancer that never got cleaned up, a storage account with expensive redundancy settings. These add up quickly and silently.

**Critical distinction:** A budget in Azure does NOT stop spending. It does NOT delete resources. It does NOT turn anything off. A budget is a monitoring and alerting tool. When you hit the threshold, Azure sends you an email. What you do with that email is up to you. This surprises most people the first time they learn it.

| Concept          | What It Means |
|------------------|---------------|
| Budget           | A spending limit you define for a scope over a time period (usually a billing month). When actual or projected spend crosses a threshold, alerts fire. |
| Reset period     | How often the budget resets. "Billing month" resets on the first of each month. |
| Actual alert     | Fires when money has already been spent and the cumulative total crosses the threshold. Example: 80% actual means you have spent $40 of your $50 budget this month. |
| Forecasted alert | Fires when Azure projects you will exceed the budget by end of the period based on current spending rate. Gives you advance warning before you actually hit the limit. |
| Action Group     | Instead of just emailing you, an action group can send an SMS, trigger a webhook, call a Logic App, or invoke an Azure Function that automatically responds to the alert. This lab uses email only. |

---

## Lab Variables and Naming Convention

Replace `[yourname]` with your actual first name, lowercase, no spaces. Use these names exactly throughout the lab.

| Variable              | Value to Use                                           |
|-----------------------|--------------------------------------------------------|
| Resource Group        | rg-lab05-gov-[yourname]                                |
| Test User UPN         | junior-dev-[yourname]@[yourtenant].onmicrosoft.com     |
| Test User Display Name| Junior Developer                                       |
| Policy Assignment Name| Restrict-VM-Sizes                                      |
| Budget Name           | Monthly-Lab-Budget                                     |
| Budget Amount         | $50                                                    |

---

## Prerequisites

| Requirement                                  | How to Verify |
|----------------------------------------------|---------------|
| Active Azure Subscription                    | Log into portal.azure.com and confirm you can see a subscription |
| Completed Week 5 Video Modules               | Review modules if needed before starting |
| Incognito or Private browser window available| You will use this to simulate the Junior Developer login without logging out of your Admin account |
| 10 minutes of patience after policy assignment | Azure Policy takes 10-30 minutes to propagate. This is normal, not a bug. |

---

## Step-by-Step Instructions

### Phase 1: Create the Lab Resource Group

The resource group is the container for everything in this lab. All governance controls you apply will be scoped to this container so they do not affect anything else in your subscription.

1. Log in to the Azure portal at https://portal.azure.com with your main admin account
2. In the search bar at the top, type **Resource Groups** and click it
3. Click **+ Create**
4. **Subscription:** your subscription should already be selected
5. **Resource group name:** `rg-lab05-gov-[yourname]`
6. **Region:** East US
7. Click **Review + create**, then **Create**

Every policy, role assignment, and budget in this lab will be anchored to this resource group. This contains your governance practice to a safe sandbox without affecting the rest of your subscription.

---

### Phase 2: RBAC - Create a User and Restrict Their Access

You are going to simulate hiring a Junior Developer. They need to see what is deployed in the environment but must not be able to create, change, or delete anything. This is the Reader role.

**Step 1: Create the user in Microsoft Entra ID**

Microsoft Entra ID is Azure's identity system. Think of it as the HR system for your cloud environment. This is the **NIST Identify function**: before you can protect access, you have to know who the person is.

1. In the search bar, type **Microsoft Entra ID** and click it
2. In the left menu, click **Users**
3. Click **+ New user** at the top, then **Create new user**
4. **User principal name:** `junior-dev-[yourname]` (Azure appends `@yourtenant.onmicrosoft.com` automatically)
5. **Display name:** `Junior Developer`
6. Under **Password:** uncheck "Auto-generate password" and type a password you will remember. You will need it in Phase 3.
7. Click **Review + create**, then **Create**

> **What is a User Principal Name (UPN)?** The UPN is the login username for this identity. The `@yourtenant.onmicrosoft.com` domain is your organisation's Azure tenant domain. This user only exists inside your Azure Active Directory and cannot log into anything outside it.

**Step 2: Assign the Reader role scoped to your resource group**

Creating the user does not give them any access. Azure starts everyone with zero permissions. You must explicitly grant access to everything. This is called "deny by default" and it is a fundamental security principle.

1. Navigate to **Resource Groups** and click **rg-lab05-gov-[yourname]**
2. In the left menu, click **Access control (IAM)**
3. Click **+ Add** at the top, then **Add role assignment**
4. On the **Role** tab: search for **Reader**, select it, click **Next**
5. On the **Members** tab: click **+ Select members**, search for **Junior Developer**, select them, click **Select**
6. Click **Review + assign**, then **Review + assign** again to confirm

You just told Azure: "The person called Junior Developer is allowed to use the Reader role, but only within this specific resource group." They can see everything inside `rg-lab05-gov-[yourname]` but cannot see or touch anything else in the subscription.

---

### Phase 3: Verify Access - The "Permission Denied" Test

Governance controls mean nothing if you never verify they work. This phase proves that the Reader role actually does what you configured. Testing your own work in both directions (blocked and allowed) is a fundamental engineering habit.

1. Open a new **Incognito** or **Private** browser window
2. Go to https://portal.azure.com in the incognito window
3. Log in as `junior-dev-[yourname]@[yourdomain].onmicrosoft.com` using the password you set in Phase 2
4. Complete any MFA setup or welcome prompts that appear
5. Navigate to **Resource Groups**. You should only see `rg-lab05-gov-[yourname]`, no other resource groups.
6. Click into `rg-lab05-gov-[yourname]`
7. Click **+ Create** inside the resource group
8. Search for **Storage Account** and click **Create**
9. Fill in any name and click **Review + create**

**Expected result:** A validation failure or red error banner saying "You do not have permission to perform this action" or "AuthorizationFailed." This is correct. This is the system working as designed. The Reader role cannot create resources.

10. Close the Incognito window and return to your Admin portal window

You have now demonstrated the **NIST Protect function** in practice. In a real organisation, this means a new hire can learn the environment without any risk of accidentally breaking production.

---

### Phase 4: Azure Policy - Prevent Expensive Configurations

RBAC controls people. Azure Policy controls configurations. Even your Admin account with full Owner access will be blocked by the policy you are about to create. Some rules should apply to everyone, no exceptions.

**The business problem this solves:** An engineer accidentally selects a `Standard_D32s_v3` (32 cores, expensive) when they meant to select a `Standard_D2s_v3` (2 cores, cheap). Without a policy, that mistake runs until someone notices the bill. With a policy, the deployment is blocked immediately at validation time.

**Step 1: Create the policy assignment**

1. In the main search bar, type **Policy** and click the Policy service
2. In the left menu under **Authoring**, click **Assignments**
3. Click **Assign policy** at the top

**Basics tab:**

4. **Scope:** click the `...` button. Select your Subscription. Then select `rg-lab05-gov-[yourname]` as the Resource Group. Click **Select**.
5. **Policy definition:** click the `...` button. In the search box, type `Allowed virtual machine size SKUs`. Select it. Click **Add**.
6. **Assignment name:** `Restrict-VM-Sizes`
7. Click **Next** to go to the Parameters tab

**Parameters tab:**

8. Uncheck **"Only show parameters that need input or review"**
9. **Allowed Size SKUs:** click the dropdown. Search for and select `Standard_B1s`. Search for and also select `Standard_B1ms`. These are the only two VM sizes this policy will allow.
10. Click **Review + create**, then **Create**

> **Policy propagation delay:** Azure Policy does not take effect instantly. It typically takes 10 to 30 minutes for a new assignment to replicate across all policy evaluation points in Azure. If the test in Phase 5 does not block your VM immediately, wait 15 minutes and try again. This is expected behaviour, not a failure.

**Step 2: Understand what you just created**

| Component              | What It Is in Plain English |
|------------------------|-----------------------------|
| Policy definition      | The rule: "Only the VM sizes in this approved list are allowed." This was pre-built by Microsoft. Azure has hundreds of built-in definitions covering security, cost, compliance, and configuration standards. |
| Policy assignment      | The act of activating the rule within a specific scope. A definition sitting unassigned does nothing. You assigned it to your resource group, so the rule is now enforced for every deployment into that group. |
| Allowed SKUs parameter | The specific values that make the rule meaningful. B1s and B1ms are the cheapest general-purpose VMs available. In production you would choose sizes appropriate for your workload requirements and budget. |

---

### Phase 5: Test the Policy

You are going to deliberately try to violate the policy to prove it works. Governance controls that are not tested are controls you cannot trust. Test both directions: blocked (violation) and allowed (permitted config).

1. Navigate to `rg-lab05-gov-[yourname]`
2. Click **+ Create**, search for **Virtual Machine**, click **Create**
3. Under **Basics**, fill in any VM name (e.g. `vm-policy-test`) and select **Ubuntu Server** as the image
4. For **Size:** click **See all sizes**. Select `Standard_D2s_v3`, a size that is NOT on your allowed list.
5. Click **Review + create**

**Expected result:** A red "Validation failed" banner. Click the error message to expand it. You should see "Policy check failed" with `Restrict-VM-Sizes` listed as the reason.

6. Now try the same VM creation with `Standard_B1s` selected as the size instead
7. Click **Review + create**

**Expected result:** Validation passes because `B1s` is on your allowed list. You do not need to complete the deployment. Once validation passes, you have proven the policy works in both directions.

> This is powerful to demonstrate in a portfolio: you did not just configure a policy, you verified it catches violations AND allows permitted configurations. Both directions of testing matter.

---

### Phase 6: Cost Management - Set Up a Budget and Alerts

You have controlled access (RBAC) and controlled configuration (Policy). Now you are going to control awareness of spend. A budget alert does not stop spending, but it gives you the earliest possible warning that something needs your attention.

> **Why does a cloud engineer need to care about cost?** Unexpected cost spikes are one of the earliest indicators of a security incident, a misconfiguration, or a runaway process. Budget alerts are as much a security tool as they are a financial one.

**Step 1: Create the budget**

1. Navigate to `rg-lab05-gov-[yourname]`
2. In the left menu, look for **Budgets** under the Cost Management section. If you do not see it, type `Budgets` in the search box within the left menu.
3. Click **+ Add**

**Create budget tab:**

4. **Name:** `Monthly-Lab-Budget`
5. **Reset period:** Billing month (resets on the first of each month)
6. **Creation date:** today (auto-filled)
7. **Expiration date:** one year from today
8. **Budget amount:** `$50`
9. Click **Next** to go to the Alert conditions tab

**Step 2: Configure alert thresholds**

Set two thresholds so you have time to act before you actually hit the limit.

**Alert condition 1 - Early warning:**
- **Alert type:** Actual
- **% of budget:** 80
- Meaning: when you have actually spent $40 of your $50 budget this month, send an alert

**Alert condition 2:** click **+ Add alert condition**
- **Alert type:** Forecasted
- **% of budget:** 100
- Meaning: if Azure projects that your current spending rate will exceed $50 before end of month, send an alert early, before you actually hit the limit

> **Actual vs. Forecasted:** An Actual alert fires after money has been spent. A Forecasted alert fires when the trend is heading toward a problem. In practice you want both: Actual gives you ground truth, Forecasted gives you time to act.

**Step 3: Set up email notification**

10. **Alert recipients:** enter your personal email address
11. **Language:** English (or your preferred language)
12. Click **Create**

> **Action Groups (optional but important to know):** Instead of just emailing one person, an Action Group can notify a distribution list, send an SMS, trigger a webhook, or invoke an Azure Function that automatically responds to the alert. In a real organisation, a budget alert might automatically tag resources for review, post to a Slack channel, or create a ticket in Jira.

**What the budget does vs. what it does not do:**

| What the Budget DOES | What the Budget Does NOT Do |
|----------------------|-----------------------------|
| Watches spending against the $50 limit | Stop, pause, or delete any running resources |
| Fires an email when actual spend hits $40 (80%) | Automatically reduce the size or count of resources |
| Fires an email when projected spend is forecast to exceed $50 | Prevent new resources from being created |
| Resets the counter on the first of each month | Override the configured resources in any way |
| Gives you an audit trail of when alerts fired | Take any action whatsoever without your involvement |

The budget is a smoke detector. It tells you there is a fire. You are still the one who has to call the fire department.

---

## How All Three Controls Work Together

Individually, each control solves one problem. Together they form a layered defence.

| Scenario | Which Control Catches It and How |
|----------|----------------------------------|
| A junior developer accidentally tries to delete the production database | RBAC: they have Reader access. Delete is a write operation. Azure returns AuthorizationFailed before anything is touched. |
| An engineer deploys a 32-core VM by mistake | Azure Policy: the Deny effect blocks the deployment at validation time, before any resource is created and before any cost is incurred. The error message names the policy that blocked it. |
| Someone leaves a load balancer running over a long weekend | Budget alert: when actual spend crosses 80% of the monthly limit, an email fires. The engineer investigates, finds the forgotten resource, and deletes it. Without the alert, the spike might not be noticed until the monthly bill arrives. |
| An attacker compromises a developer account and starts spinning up VMs for crypto mining | Both Policy and Budget catch this. Policy blocks expensive VM sizes. If they use allowed sizes, the budget alert fires when spend spikes unexpectedly. Two independent controls, neither of which requires human monitoring to catch the problem. |

---

## Verification Checklist

| Check | What You Should Be Able to Confirm |
|-------|-------------------------------------|
| Junior Developer user exists | Microsoft Entra ID then Users: junior-dev-[yourname] appears in the list |
| Reader role assigned | rg-lab05-gov-[yourname] then Access control (IAM) then Role assignments tab: Junior Developer listed with Reader role |
| Permission denied confirmed | Incognito test showed AuthorizationFailed when Junior Developer tried to create a Storage Account |
| Policy assigned | Policy then Assignments: Restrict-VM-Sizes appears scoped to your resource group |
| Policy blocks violations | VM creation with Standard_D2s_v3 showed "Validation failed - Policy check failed: Restrict-VM-Sizes" |
| Policy allows approved sizes | VM creation with Standard_B1s showed validation passing |
| Budget created | rg-lab05-gov-[yourname] then Budgets: Monthly-Lab-Budget appears with $50 limit |
| Both alert thresholds set | Budget shows 80% Actual alert and 100% Forecasted alert configured |
| Email recipient set | Budget then Alert recipients shows your email address |

---

## Troubleshooting

| Issue | Root Cause | Resolution |
|-------|------------|------------|
| Junior Developer can still create resources | Role was assigned at the wrong scope, possibly the subscription level | Go to rg-lab05-gov-[yourname] then Access control (IAM) then Role assignments. Confirm the Reader assignment appears here at the resource group level. If not, add it at this scope. |
| Policy is not blocking the VM | Policy assignment has not finished propagating (takes 10-30 minutes) | Wait 15 minutes and try again. If it still does not block after 30 minutes, check Policy then Assignments and confirm Restrict-VM-Sizes is listed with your resource group as the scope. |
| Cannot find Budgets in the left menu | Cost Management may not be visible on the left panel for all subscription types | Go to Cost Management + Billing in the main search bar and navigate to Budgets from there. |
| Incognito login prompts for authenticator app | Microsoft Entra ID requires MFA setup on first login | Complete the MFA setup using your phone. This is normal and is the NIST Protect function in action firsthand. |
| Policy definition "Allowed virtual machine size SKUs" not found | Search term slightly off | Search for `virtual machine size` without quotes. Select the definition that mentions allowed sizes or SKUs. |
| Budget creation fails with a permissions error | Account may not have Cost Management write permissions | Go to Subscriptions then your subscription then Access control (IAM). Confirm your account has the Cost Management Contributor role or Owner role. |

---

## Interview Talking Points

Practice these answers out loud before an interview.

**What is RBAC and why does it matter?**
"RBAC stands for Role-Based Access Control. It is how you enforce the principle of least privilege in Azure. You assign people the minimum permissions they need to do their job and nothing more. In practice this means if a junior developer has Reader access and accidentally tries to delete a database, Azure blocks them before anything is touched. The blast radius of any mistake is limited to what that person is allowed to do."

**What is Azure Policy and how is it different from RBAC?**
"RBAC controls who can act. Azure Policy controls what configurations are allowed, regardless of who is doing it. Even an Owner account will be blocked by a Deny policy. RBAC is about identity. Policy is about configuration. A mature governance model uses both together."

**What is the NIST Cybersecurity Framework and how does governance relate to it?**
"NIST CSF organises security into five functions: Identify, Protect, Detect, Respond, and Recover. Creating users in Entra ID is Identify. RBAC and Policy are Protect. Budget alerts are Detect. Responding to a budget alert spike is Respond. Deleting test resources after a lab is Recover. Every governance control maps into one of these."

**Does a budget in Azure stop spending when the limit is reached?**
"No, and this surprises a lot of people. A budget is a monitoring and alerting tool. It sends you an email when spend crosses a threshold. It does not delete resources, pause VMs, or prevent new deployments. If you want automated response, you pair the budget with an Action Group that triggers a function or a webhook. The budget is the smoke detector. You are still the one who calls the fire department."

**What is the difference between a Forecasted and an Actual budget alert?**
"An Actual alert fires when money has already been spent, for example when 80% of the monthly budget is consumed. A Forecasted alert fires when the current spending trend projects you will exceed the budget before month end, so you get advance warning before the limit is actually hit. Both matter: Actual gives you ground truth, Forecasted gives you time to act."

---

## Cleanup

Always clean up after a lab. Leaving resources running costs money and clutters your environment. This is the **NIST Recover function**: restoring your environment to a known clean state after the exercise.

**Delete the resource group:**
1. Navigate to `rg-lab05-gov-[yourname]`
2. Click **Overview** then **Delete resource group**
3. Type the resource group name to confirm
4. Click **Delete**

Deleting the resource group removes everything inside it including the policy assignment scoped to it and the budget.

**Delete the test user:**
1. Navigate to **Microsoft Entra ID** then **Users**
2. Search for `junior-dev-[yourname]`
3. Click on the user, then **Delete**, and confirm

> Users left in Entra ID are unused identities that add to your attack surface. An unused account that no one is monitoring is a potential entry point for an attacker.

**Verify cleanup:**
- Go to **Resource Groups** and confirm `rg-lab05-gov-[yourname]` is no longer listed
- Go to **Entra ID** then **Users** and confirm `junior-dev-[yourname]` is no longer present

Confirm your cleanup worked before ending the lab session. An unchecked resource that keeps running is exactly the kind of thing a budget alert is designed to catch. It is better to delete it than to rely on the alert.

---

*Lab authored by **Jair Smith** · Azure Cloud Security Series · Lab 05 of ongoing curriculum*
