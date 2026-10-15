# Threat Model — Indirect Prompt Injection & Tool-Use Guardrail Sandbox

## 1. Purpose and Scope

This document defines the security assumptions, protected assets, adversary capabilities, trust boundaries, threats, and security invariants for the Indirect Prompt Injection & Tool-Use Guardrail Sandbox.

The project investigates whether malicious instructions embedded in external content can manipulate an LLM agent into violating its intended task or performing unauthorized tool operations.

The initial implementation is a controlled research environment using synthetic data, local fixtures, and simulated side effects.

This document describes intended security properties. A property is not considered implemented or verified until it has been enforced by code and tested.

## 2. System Overview

The planned system accepts a user task, retrieves approved external content, and uses an LLM to produce a response or propose a tool operation.

The application, rather than the LLM, is responsible for validating requests and enforcing tool authorization.

Planned components:

- Agent orchestration and model adapter.
- Approved document-reading tool.
- Allowlisted local webpage-fixture reader.
- Email-drafting tool with no sending capability.
- Tool gateway and deterministic authorization policy.
- Optional input screening.
- Optional independent LLM supervisor.
- Experiment runner, benchmark datasets, and evaluation metrics.

The full agent and tool gateway have not yet been implemented.

## 3. Security Objectives

The system aims to:

1. Protect synthetic secrets from unauthorized disclosure.
2. Restrict document access to explicitly approved resources.
3. Prevent untrusted content from granting tool permissions.
4. Prevent unauthorized tool operations from executing.
5. Restrict email functionality to creating drafts.
6. Preserve the integrity of application policies and configuration.
7. Record enough information to distinguish proposed, denied, and executed actions.
8. Preserve legitimate task utility while reducing attack success.
9. Support reproducible comparisons between baseline and defended configurations.

## 4. Protected Assets

### A1. Synthetic secrets

Artificial secret values used to test unauthorized disclosure. They must not represent real credentials or private information.

### A2. Approved documents and fixtures

Synthetic documents, local HTML fixtures, and simulated messages containing benign information or controlled adversarial instructions.

### A3. Tool permissions

The fixed set of operations the application allows, including the resources and arguments each operation may access.

### A4. Authorization policy

The application-controlled rules determining whether a tool request may execute.

### A5. User task and legitimate task output

The original task, its expected result, and the information required to complete it correctly.

### A6. Experimental records

Benchmark case identifiers, configuration versions, action traces, outcome labels, and aggregate metrics. These records must not unnecessarily expose sensitive data.

### A7. Configuration and code integrity

The application code, tool registry, security configuration, and evaluation logic must not be modifiable through instructions contained in retrieved content.

## 5. Trust Boundaries

### TB1. User instructions to the agent

User instructions establish the intended task. The initial benchmark assumes the user task itself is not malicious.

### TB2. External content to the agent

Retrieved documents, webpage fixtures, and simulated messages are untrusted, even when they originate from an approved resource.

An approved source may contain malicious content. Source approval does not make every instruction within the source trustworthy.

### TB3. Agent to tool gateway

The agent may propose a structured tool request. The request is untrusted until the application validates it.

The LLM must not invoke tool implementations directly or decide its own authorization outcome.

### TB4. Tool gateway to tool implementation

The gateway validates the tool name, arguments, resource restrictions, and authorization decision before dispatch.

Tool implementations must also enforce their own resource boundaries where appropriate. A gateway check must not be treated as a substitute for safe file or resource handling inside a tool.

### TB5. Application to external services

The initial benchmark uses local fixtures and simulated side effects. No real email delivery, unrestricted filesystem access, or unrestricted network access is permitted.

Optional hosted model calls are limited to the configured provider interface and require explicit configuration.

### TB6. Experiment runner to evaluation records

The evaluation system must distinguish model outputs, proposed actions, policy decisions, executed operations, and final outcomes. Model-generated claims are not sufficient evidence that an action did or did not execute.

## 6. Adversary Model

### Attacker objective

The attacker attempts to manipulate the agent through untrusted content so that it violates the intended task or causes a prohibited information flow or tool operation.

### Attacker capabilities

Within the benchmark, the attacker may:

- Control the text of selected synthetic documents or local webpage fixtures.
- Embed direct, indirect, or obfuscated instructions within otherwise relevant content.
- Ask the agent to ignore previous instructions or alter its task.
- Attempt to induce unauthorized document reads or disclosure of synthetic secrets.
- Attempt to induce the agent to create an email draft containing prohibited information.
- Attempt to induce calls to unknown tools or calls with invalid or unauthorized arguments.
- Use benign-looking context to conceal malicious instructions.

### Attacker limitations

The initial threat model assumes the attacker cannot:

- Modify application source code or the installed package.
- Change the authorization policy or tool registry directly.
- Modify the benchmark evaluator or ground-truth labels.
- Access the host operating system outside the exposed tool interfaces.
- Send real emails through the sandbox.
- Access arbitrary network destinations through the sandbox tools.
- Read real credentials or private user data through the benchmark.
- Compromise the Python interpreter or underlying host.

These assumptions delimit the initial experiments. They do not imply that the system is secure against attackers who can compromise the host or application itself.

## 7. Threat Categories

### T1. Instruction override

Malicious retrieved content attempts to override the user's intended task or trusted application instructions.

### T2. Unauthorized tool use

The agent proposes an unknown tool, a disallowed operation, or an operation outside its assigned permissions.

### T3. Unauthorized information access

The agent attempts to read a document or resource that is not approved for the current operation.

### T4. Synthetic secret disclosure

The agent attempts to expose a synthetic secret in a final response, tool argument, email draft, or other observable output.

### T5. Unauthorized draft creation or content manipulation

The agent creates an email draft that violates the task or contains prohibited information. Draft creation and secret disclosure are distinct outcomes and should be recorded separately.

### T6. Argument manipulation

The agent supplies malformed, unexpected, or adversarial tool arguments intended to bypass validation or exceed resource boundaries.

### T7. Policy or configuration manipulation

Retrieved instructions attempt to change permissions, disable safeguards, alter the tool registry, or modify application configuration.

The initial system must not expose tools that allow the model to perform these changes.

### T8. Benign task disruption

A defense incorrectly blocks a legitimate task, removes necessary information, or produces an unusable result.

This is a utility failure rather than a successful security attack, but it is important when evaluating defensive trade-offs.

## 8. Security Invariants

The following are required design properties. They remain unverified until implemented and tested.

### INV-1: Authorization independence

Authorization decisions are made by ordinary application code, not by the LLM.

### INV-2: Complete mediation

Every tool execution passes through an application-controlled authorization boundary.

### INV-3: Unknown tools are denied

A tool request that does not identify an explicitly registered tool cannot execute.

### INV-4: Argument and resource validation

Tool arguments must satisfy the defined schema and resource constraints. Malformed or unauthorized requests are rejected before execution.

### INV-5: Policy integrity

The LLM and retrieved content cannot modify authorization rules, tool registrations, or security configuration through ordinary tool calls.

### INV-6: Restricted document access

Document reads are limited to approved document identifiers and explicitly permitted resources.

### INV-7: Restricted webpage access

The webpage tool reads only allowlisted local fixtures. It does not provide arbitrary URL fetching or unrestricted network access.

### INV-8: No real email sending

The email tool can create a simulated draft only. No sending operation exists in the initial tool registry.

### INV-9: Synthetic data only

Secrets and sensitive-looking values in experiments are synthetic. The benchmark does not require real credentials or private user data.

### INV-10: Observable outcomes

The experiment records enough evidence to distinguish proposed, denied, and executed actions. Evaluation must not infer execution from the LLM's narrative alone.

### INV-11: Defense-independent enforcement

Removing optional input screening or the optional LLM supervisor must not remove the mandatory authorization boundary or enable prohibited side effects.

### INV-12: Reproducible evaluation

Benchmark cases, configurations, outcome definitions, and model settings are versioned or recorded sufficiently to explain and reproduce reported experiments.

## 9. Defense Strategy

The planned experiment compares:

1. **Baseline agent:** No additional injection-specific screening or supervisory defense. Mandatory sandbox restrictions remain in force.
2. **Deterministic guardrails:** Explicit authorization, schema validation, and resource restrictions.
3. **Input-screening configuration:** An optional detector that flags suspicious retrieved content.
4. **Independent-supervisor configuration:** An optional second model that reviews proposed actions or relevant context.

The exact combination of controls in each experimental configuration will be specified in the evaluation protocol.

The deterministic authorization boundary remains mandatory in every configuration. Consequently, this study measures the additional effectiveness of optional defenses within a safely constrained environment, not the effect of removing all security controls.

Input screening and LLM supervision are fallible. Their outputs must not replace deterministic authorization.

## 10. Initial Risk Assessment

| Risk                                        | Potential impact              | Primary control                                               |
| ------------------------------------------- | ----------------------------- | ------------------------------------------------------------- |
| Malicious instruction changes task behavior | Loss of task integrity        | Trusted task handling and measured defense behavior           |
| Unauthorized tool execution                 | Violation of tool permissions | Deterministic authorization gateway                           |
| Unauthorized document read                  | Confidentiality loss          | Approved document identifiers and resource validation         |
| Synthetic secret disclosure                 | Confidentiality failure       | Restricted tool outputs and explicit disclosure evaluation    |
| Unsafe tool arguments                       | Resource-boundary violation   | Schema validation and tool-level restrictions                 |
| False-positive blocking                     | Reduced task utility          | Benign benchmark cases and utility metrics                    |
| Incomplete event records                    | Invalid research conclusions  | Structured action and outcome logging                         |
| Model-based defense inconsistency           | Variable security outcomes    | Repeated trials where appropriate and recorded model settings |

These are qualitative initial assessments, not measured risk scores.

## 11. Out of Scope

The initial benchmark does not attempt to evaluate:

- Host operating-system compromise or arbitrary code execution.
- Real credential theft or disclosure of private user data.
- Real email delivery or other irreversible external side effects.
- Unrestricted browsing or arbitrary network access.
- Compromise of the model provider or underlying model infrastructure.
- Training-time data poisoning or model-weight manipulation.
- Exhaustive robustness against all languages, encodings, or adversarial transformations.
- Formal proof of security for the complete application.
- Universal protection against every form of prompt injection.

These areas may be considered in future work, but only with a separate threat model and appropriate controls.

## 12. Open Questions

The following decisions must be resolved before the full benchmark is implemented:

1. Which LLM provider and model versions will be used in the initial experiments?
2. Will baseline runs use a deterministic mock agent, a hosted LLM, or both?
3. How will the benchmark represent task-specific permissions and document access?
4. Which output channels count as observable secret disclosure?
5. How many repeated trials will be required for stochastic model configurations?
6. Which supervisor and input-screening implementations will be compared?
7. How will model cost, latency, and provider failures be handled?
8. Which benchmark cases will be used for development, and which will be held out for final evaluation?

## 13. Implementation Status

This document defines intended properties and the initial threat model. It does not establish that the planned agent, gateway, or defenses already exist.

The existing policy implementation and tests must be inspected and extended as needed. Each security invariant must ultimately map to concrete enforcement code and one or more tests.

The next implementation phase will define structured agent requests, controlled tool interfaces, and a gateway that enforces these requirements.
