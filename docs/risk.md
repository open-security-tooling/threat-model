# Risk

The goal: any developer can look at a risk level and **agree or disagree with it in five seconds**, because they can see exactly why it was given. That rules out CVSS-style formulas with decimal scores.

## Three questions

Every threat answers three questions in plain words.

### 1. Who could do it? (`who`)

The least access someone needs to pull it off.

| `who` | Means | Think of |
|---|---|---|
| `anyone` | Anyone on the internet, no account needed | A bot scanning the web |
| `any-user` | Anyone with an account, including free sign-ups | A curious or malicious customer |
| `insider` | Someone inside: employees, contractors, partners with access | A support agent, a compromised laptop |
| `privileged` | Admins, ops, people with production access | An engineer with prod credentials |
| `physical` | Someone with the device in their hands | A stolen phone or laptop |

### 2. How hard is it? (`effort`)

| `effort` | Means |
|---|---|
| `trivial` | Copy-paste or point-and-click. Tools or tutorials exist. Minutes. |
| `moderate` | Needs some skill, time or luck. Hours to days. |
| `hard` | Needs rare access, deep expertise or many things to line up. |

### 3. How bad is it? (`impact`)

| `impact` | Means | Examples |
|---|---|---|
| `low` | Annoying, no real harm | Cosmetic defacement, a short blip for one user |
| `medium` | Limited harm to some users, or a recoverable outage | One customer's data, a degraded service for an hour |
| `high` | Serious harm to many users or the business | Many customers' personal data, lost money, a day of downtime |
| `critical` | Everything is at stake | Full takeover, all customer data, secrets or signing keys |

`impact_note` says *what specifically* breaks. The tool suggests an impact from the most sensitive `data` the threat can reach, but a human decides.

## From answers to risk

**Likelihood** combines *who* and *effort*:

|  | `trivial` | `moderate` | `hard` |
|---|---|---|---|
| `anyone` | likely | likely | possible |
| `any-user` | likely | possible | unlikely |
| `insider` | possible | unlikely | unlikely |
| `privileged` / `physical` | unlikely | unlikely | rare |

**Risk** combines likelihood and impact:

|  | `low` | `medium` | `high` | `critical` |
|---|---|---|---|---|
| likely | medium | high | critical | critical |
| possible | low | medium | high | critical |
| unlikely | low | low | medium | high |
| rare | low | low | low | medium |

Both tables are part of the format spec and are versioned with it, so everyone gets the same answer for the same inputs. Orgs can supply their own tables in a config file. A different risk appetite is a legitimate reason to.

## The explanation

The tool turns the inputs into one sentence:

> **High:** anyone who signs up can do this in minutes, and it exposes every customer's invoices.

> **Medium → Low once "Rate-limit login" is done:** anyone on the internet can try, but it takes days of guessing; with rate limiting it would take years.

The sentence is built from templates per `who`, `effort` and `impact`, plus the `impact_note`. It's deterministic and needs no AI. Agents can always ask for it with `threat explain <id> --json` or the MCP `explain_risk` tool.

## Overrides

Sometimes the tables are wrong for a case. You can set the result directly, but you have to say why:

```yaml
    risk:
      override: critical
      reason: Regulators treat any leak of this data as a reportable breach.
```

Overrides are shown clearly in the web app and the report, so they can't hide.

## Residual risk

The risk shown is calculated **after** applying the `effect` of every linked mitigation that's `done`. Mitigations still `planned` or `in-progress` show what the risk *will* become. That's a strong argument for prioritising them: *"Doing this one fix takes 4 threats from High to Low."*

## What we deliberately don't do

- **No CVSS.** It's built for scoring individual vulnerabilities, not for design-level threats, and its vectors are opaque to most devs. If the security team wants CVSS, it can go in `refs`.
- **No decimal scores.** 6.8 vs 7.1 is false precision for a design discussion.
- **No hidden weights.** Every input is visible in the file, and every rule is in this doc.
