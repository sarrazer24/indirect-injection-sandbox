# Indirect Prompt Injection & Tool-Use Guardrail Sandbox

A reproducible research sandbox for investigating **indirect prompt injection attacks against tool-using LLM agents** and evaluating the effectiveness of security guardrails.

The project aims to demonstrate practical AI security engineering through controlled experiments, deterministic authorization policies, structured validation, adversarial test cases, and quantitative evaluation.

> **Project status:** Foundation and initial policy tests in progress. The full agent, attack benchmark, and defense evaluation pipeline are planned.

## Research Objectives

Large language model (LLM) agents can retrieve external content and use tools to perform tasks. That external content may contain malicious instructions designed to manipulate the agent into violating its intended behavior.

This project will investigate:

- How indirect prompt injection attacks influence tool-using agents.
- How an agent behaves when exposed to malicious instructions embedded in retrieved documents or webpages.
- How deterministic authorization policies and other guardrails affect attack success.
- How security defenses compare against an unguarded baseline.
- What trade-offs defenses introduce in terms of task completion, false positives, and usability.

The goal is to build a controlled and reproducible experimental environment, not to claim that any single defense completely eliminates prompt injection.

## Planned Features

- **Controlled agent environment:** An agent with a limited set of explicitly approved tools.
- **Indirect prompt injection benchmark:** Synthetic malicious and benign documents with reproducible test cases.
- **Deterministic authorization:** Tool permissions enforced outside the LLM.
- **Input screening:** Optional detection of suspicious instructions in retrieved content.
- **Output validation:** Validation of proposed actions and structured responses.
- **Supervisory defenses:** Optional additional checks before sensitive tool actions.
- **Experimental evaluation:** Comparison of attack success rates and task performance across defense configurations.
- **Reproducible reporting:** Structured experiment results and analysis using pandas.

## Technology Stack

| Component                | Technology                                        |
| ------------------------ | ------------------------------------------------- |
| Language                 | Python 3.13                                       |
| Data validation          | Pydantic                                          |
| Testing                  | pytest                                            |
| Coverage                 | pytest-cov                                        |
| Linting and formatting   | Ruff                                              |
| Data analysis            | pandas                                            |
| Optional LLM integration | Provider-independent adapter for a hosted LLM API |
| Optional web fixtures    | HTTPX and BeautifulSoup                           |

Optional LLM and web integrations will be isolated from the core security logic so that baseline tests can run without external services.

## Architecture

The repository is organized around separation of concerns.

```text
indirect-injection-sandbox/
├── configs/
├── docs/
├── results/
├── scripts/
├── src/
│   └── injection_sandbox/
│       ├── agent/
│       ├── tools/
│       ├── security/
│       ├── evaluation/
│       ├── datasets/
│       │   ├── attacks/
│       │   ├── benign/
│       │   └── fixtures/
│       ├── config.py
│       └── __init__.py
├── tests/
│   ├── unit/
│   ├── integration/
│   └── benchmark/
├── .env.example
├── .gitignore
├── pyproject.toml
└── README.md
```

The exact contents of these directories will evolve as implementation progresses.

### Core responsibilities

- `agent/`: Agent orchestration, prompts, and structured schemas.
- `tools/`: Approved document reading, controlled webpage fixture reading, and email drafting.
- `security/`: Authorization policies, input screening, output validation, and optional supervisory checks.
- `evaluation/`: Benchmark execution, metrics, and reporting.
- `datasets/`: Synthetic attack examples, benign examples, and controlled fixtures.
- `tests/`: Unit tests, integration tests, and benchmark validation.
- `scripts/`: Reproducible experiment and development commands.
- `configs/`: Experiment and application configuration.
- `results/`: Generated experimental outputs and reports.

## Security Principles

Security controls are designed to operate independently of the LLM's instructions.

1. **Untrusted external content:** Retrieved documents and webpages are treated as untrusted data, never as authoritative instructions for granting permissions.
2. **External authorization:** Tool access is checked by deterministic application code rather than delegated to the LLM.
3. **Least privilege:** Only explicitly approved tools and operations are permitted.
4. **Synthetic secrets:** Experiments use synthetic secrets and controlled fixtures rather than real credentials or private data.
5. **No real email sending:** Email functionality is restricted to drafting and validation.
6. **Restricted access:** No unrestricted filesystem access or unrestricted network access is enabled.
7. **Secret management:** API keys and credentials must never be committed to version control.
8. **Defense evaluation:** Defenses are assessed empirically against the same benchmark scenarios used for the baseline.

These controls reduce experimental risk but do not guarantee that every possible attack will be detected.

## Getting Started

### Prerequisites

- Python 3.13
- Git
- Windows PowerShell, or an equivalent terminal

The project currently targets Python 3.13.

### 1. Clone the repository

```powershell
git clone https://github.com/sarrazer24/indirect-injection-sandbox.git
cd indirect-injection-sandbox
```

### 2. Create a virtual environment

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, consult the Python documentation or use the virtual environment's Python executable directly.

### 3. Install the project

Upgrade pip:

```powershell
python -m pip install --upgrade pip
```

Install the project and its development dependencies:

```powershell
python -m pip install -e ".[dev]"
```

This command assumes the `dev` optional dependency group is configured in `pyproject.toml`.

### 4. Configure environment variables

Use `.env.example` as a reference for supported environment variables.

If local configuration is needed, create a `.env` file from that template and populate only the values required for your environment.

Never commit `.env` or real API keys.

The initial tests should not require an API key or an external LLM service.

## Development and Verification

Run the unit tests:

```powershell
python -m pytest -v
```

Run tests with a coverage report:

```powershell
python -m pytest --cov=injection_sandbox --cov-report=term-missing
```

Check code quality:

```powershell
python -m ruff check .
```

Check formatting:

```powershell
python -m ruff format --check .
```

Automatically format supported Python files:

```powershell
python -m ruff format .
```

Run these checks before committing changes.

## Research Evaluation Plan

The planned evaluation will compare an unguarded baseline against selected defense configurations using a shared benchmark.

Potential metrics include:

- **Attack Success Rate (ASR):** The proportion of eligible attack trials in which the defined security violation occurs.
- **Task Success Rate:** The proportion of trials in which the agent completes the intended benign task.
- **False Positive Rate:** The proportion of benign trials incorrectly flagged or blocked by a defense.
- **Tool Authorization Violations:** The number of unauthorized tool actions attempted or executed, reported separately.
- **Latency and cost:** The overhead introduced by optional model-based defenses.

The benchmark will define trial outcomes and denominators explicitly. Experiments will use fixed configurations and recorded random seeds where applicable.

Results will distinguish between attempted unauthorized actions and actions actually executed. A blocked malicious attempt is not equivalent to a successful attack.

## Roadmap

- [x] Create the initial repository structure.
- [x] Configure the Python package and development environment.
- [x] Add initial deterministic policy tests.
- [ ] Complete foundation verification and documentation.
- [ ] Implement the agent and approved tool interfaces.
- [ ] Construct synthetic attack and benign benchmark datasets.
- [ ] Implement reproducible baseline experiments.
- [ ] Add and evaluate defense mechanisms.
- [ ] Analyze results and generate research reports.
- [ ] Document limitations, failure cases, and conclusions.

Checklist items reflect the intended project workflow and should be updated as implementation is verified.

## Responsible Research

This project is intended for controlled AI security research and defensive evaluation.

Experiments should use synthetic data, local fixtures, restricted tools, and explicitly authorized services. The sandbox must not be used to access private data, execute unauthorized actions, or send real emails.

Findings should report both successful defenses and failure cases. A defense that performs well on a limited synthetic benchmark should not be presented as universally robust.

## License

No license has been selected yet. Until one is added to the repository, do not assume that the project is available for unrestricted redistribution or reuse.
