**Project Proposal**

**Project Title:** _An Agentic AI Approach to Context-Aware Code Vulnerability Detection_

**Researcher: DIMOSTHENIS-NEKTARIOS NIKOUDIS-ALESSIOS**

**Dissertation Coordinator:** Dr Ioannis A. Pikrammenos

**Dissertation Supervisor:** Dr Ioannis A. Pikrammenos

**Background and literature review:**

_Traditional vulnerability detection tools, including modern AI-powered solutions like Snyk Code and DeepCode, suffer from a fundamental limitation:_ **_lack of contextual understanding_**_. These tools operate as sophisticated pattern matchers that apply the same vulnerability checks regardless of application context, miss vulnerabilities that require understanding of business logic, and generate high false-positive rates due to their context-blind scanning approach._ _Recent empirical evidence supports this limitation: Recent empirical evidence supports this limitation: Ding et al. (2025) found that while LLMs detected 69 out of 120 vulnerabilities, state-of-the-art static analysis tools detected only 27, highlighting the severe constraints of pattern-based approaches._

**_The rise of agentic AI systems_**

_The recent success of agentic coding tools has demonstrated a paradigm shift in how AI can interact with code. Tools like Cursor, Claude Code and OpenAI Codex can autonomously navigate file systems and execute commands, make intelligent decisions about what to explore next, maintain context across multiple operations, and adapt their strategies based on discovered information. Jimenez et al. (2024) introduced the SWE-bench benchmark using 2,294 real GitHub issue-PR pairs, demonstrating that agentic systems like Devin achieved 13.86% success versus the previous 1.96% baseline - a sevenfold improvement that validates the transformative potential of agentic approaches._

**_Why this approach is now feasible:_**_  
Recent advances in large language models like GPT-4.1, Claude 4, and Gemini 2.5 have made this new approach possible. These models now demonstrate strong reasoning capabilities, allowing them to understand architectural patterns and make informed security decisions. They can use command-line tools consistently and accurately, with minimal hallucinations. They also retain context across long sessions, enabling coherent and effective exploration. Most importantly, autonomous agents powered by these models can reliably make decisions without constant human oversight. Furthermore, recent work on global counterfactual explainability (Emiris et al., 2024; Kavouras et al., 2023) provides valuable frameworks for understanding and validating AI-driven security analysis tools, ensuring that our agentic approach can be audited for fairness and interpretability._

**_The Opportunity: Bringing agentic approaches to security:_**_  
While agentic AI has transformed areas like code generation and debugging, security analysis still relies heavily on static analysis techniques. This gap represents a significant opportunity - while considerable research has focused on the security vulnerabilities of AI agents themselves (Chen et al., 2024), the potential for leveraging agentic approaches to enhance security analysis remains largely unexplored. This asymmetry suggests that the very capabilities that make AI agents powerful - autonomous exploration, contextual reasoning, and adaptive decision-making - could be transformative when applied to vulnerability detection. This project aims to apply the agentic paradigm to vulnerability detection. The goal is to develop a system that first understands the type of application it is analyzing, then adapts its vulnerability checks based on context. It should intelligently explore the codebase using appropriate tools and reason about actual risk to prioritize findings based on their real-world exploitability._

**Rationale of Project:**

_Current security tools are limited because they lack the contextual understanding that human security researchers naturally employ. When a security expert analyzes code, they first ask: "What kind of application is this? What are its critical assets? What would an attacker target?"_

_By leveraging the agentic approach proven successful in tools like Cursor, Claude Code or OpenAI Codex, I can create a security analyzer that:_

- _Reduces false positives through contextual filtering_
- _Discovers complex, business-logic vulnerabilities missed by pattern matching_
- _Provides remediation advice tailored to the specific application context_

**Aims and/or Hypothesis of your Research:**

_Develop and evaluate an autonomous security agent inspired by modern coding assistants that:_

1. _Autonomously explores codebases using CLI tools to build contextual understanding_
2. _Adapts vulnerability detection strategies based on application type and architecture_
3. _Discovers complex, context-specific vulnerabilities through intelligent exploration_
4. _Generates prioritized reports with context-aware remediation guidance_

**_Research Hypothesis_**

**_Primary hypothesis_**_: An agentic approach to vulnerability detection that first builds contextual understanding will significantly outperform traditional pattern-based tools in accuracy and actionability._

**_Secondary hypotheses_**_: Context-aware detection is expected to reduce false positive rates by tailoring vulnerability checks to the specific characteristics of the application. Additionally, autonomous exploration should enable the discovery of multi-file vulnerabilities that static analysis tools can miss due to their limited scope._

**Overall Research Question**: _Can agentic AI systems, inspired by successful coding assistants, overcome the contextual understanding limitations of current security tools through autonomous exploration and adaptive vulnerability detection?_

**Methodology**

**System Design:** I will c_reate a CLI application that employs a multi-stage agentic architecture that mirrors how human security researchers analyze code. Specifically, it will consist of the following stages:_

**_Stage 1: Context discovery  
_**_The agent autonomously enumerates the file system with tree and find to map the technology stack, infer the application's core logic, and identify its critical assets._

**_Stage 2: Adaptive strategy planning  
_**_The agent programmatically builds a tailored search strategy by executing context-specific threat modeling to select vulnerability classes and generate custom regex patterns for high-priority targets._

**_Stage 3: Intelligent exploration  
_**_The agent systematically executes targeted grep/ripgrep searches, automatically tracks data flow and dependencies across files, and iteratively refines its queries based on real-time findings._

**_Stage 4: Contextual analysis  
_**_For each potential vulnerability, the agent automatically correlates technical data with the application's business context to assess the exploitability vector, calculate business impact, and triage false positives. This approach builds on recent advances like DeepDFA (Steenhoek et al., 2024), which demonstrated that hybrid architectures combining dataflow analysis with deep learning detected 8.7 out of 17 real-world vulnerabilities while baseline approaches detected none._

**_Stage 5: Actionable reporting  
_**_Finally, the agent automates the generation of a prioritized report, detailing context-aware severity scores, application-specific remediation guidance, and developer-centric vulnerability explanations._

**Validation Methodology:**

_Validation Methodology: To validate the effectiveness of our approach, we will leverage recent advances in counterfactual explainability research. Specifically, we will employ methodologies from GLANCE (Emiris et al., 2024), which provides global counterfactual explanations for machine learning models, and the Fairness Aware Counterfactuals for Subgroups (FACTS) framework (Kavouras et al., 2023) to audit subgroup fairness in our vulnerability detection results. These frameworks will help ensure that our agentic approach can be audited for fairness and interpretability._

**Ethical Considerations:**

_I will test only on intentionally vulnerable applications or obtain explicit permission from the authors for any third-party repository analysis. I will also ensure that any API calls are rate limited to prevent resource abuse._

**Please submit together with this form:**

**1\. Ethical Approval Form**

**2\. Example Information Sheet**

**3\. Example Consent Form**

**Proposed Analysis of Data:**

_The tool will be tested using the OWASP Benchmark v1.2, a standardized test suite containing approximately 3,000 test cases covering common vulnerability categories. Results will be compared against the published Commercial SAST Average baseline, which represents the aggregated performance of six commercial Static Application Security Testing tools. While the OWASP Benchmark focuses on Java applications, it provides the most rigorous and industry-accepted methodology for comparative analysis. The benchmark includes both true vulnerabilities and false positive test cases, enabling comprehensive accuracy assessment. Proposed metrics for comparison include:_

**_Quantitative Metrics_**

_1\._ **_True Positive Rate (TPR)_**_: Percentage of actual vulnerabilities correctly identified compared to the commercial average_

_2\._ **_False Positive Rate (FPR)_**_: Percentage of false alarms compared to the commercial baseline_

_3\._ **_Benchmark Score_**_: Overall performance metric calculating the distance from random guessing, enabling direct comparison with industry standards_

_4\._ **_Efficiency_**_: Scanning time per test case and resource usage relative to the ~3,000 test cases_

**_Vulnerability Category Analysis_** _Performance will be evaluated across specific vulnerability types including SQL Injection, XSS, Command Injection, Path Traversal, and others, comparing detection rates against commercial tool averages for each category_

**_Risk Assessment_**_\*: Vulnerabilities will be analyzed by CWE classification to demonstrate capability across different security risk categories, with performance compared to the commercial baseline for each vulnerability class_

**Proposed Timeline**

**_From June 1<sup>st</sup>, 2025 until September 21<sup>st</sup>, 2025 (13 weeks)_**

| **Period of _01/06-21/09/2025_** |     | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **Week** | **1** | **2** | **3** | **4** | **5** | **6** | **7** | **8** | **9** | **10** | **11** | **12** | **13** |
| Literature Review | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; |
| Project Code Foundation | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; |
| Agentic Scanning Implementation | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; |
| Review the project | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; |
| Conclusions-Recommendations | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; |
| Introduction - Executive Summary | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; |
| Finalizing the project | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; |
| Submission of the project | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; |
| &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; | &nbsp; |

**References**

1. _Chen, Y., Lan, Y., Fang, Z., Fang, X., Liu, Q., Zhang, W., & Shi, J. (2024). AI agents under threat: A survey of key security challenges and future pathways. ACM Computing Surveys. <https://doi.org/10.1145/3716628>_
2. _Emiris, I., Fotakis, D., Giannopoulos, G., Gunopulos, D., Kavouras, L., Markou, K., Psaroudaki, E., Rontogiannis, D., Sacharidis, D., Theologitis, N., Tomaras, D., & Tsopelas, K. (2024). GLANCE: Global Actions in a Nutshell for Counterfactual Explainability. arXiv preprint arXiv:2405.18921._
3. _Ding, Y., Fu, Y., Ibrahim, O., Sitawarin, C., Chen, X., Alomair, B., Wagner, D., Ray, B., & Chen, Y. (2025). Vulnerability detection with code language models: How far are we? In Proceedings of the 47th International Conference on Software Engineering (ICSE '25). ACM. <https://doi.org/10.1145/3597503.3639100>_
4. _Jimenez, C., Yang, J., Wettig, A., Yao, S., Pei, K., Press, O., & Narasimhan, K. (2024). SWE-bench: Can language models resolve real-world GitHub issues? In Proceedings of the 12th International Conference on Learning Representations (ICLR 2024)._
5. _Kavouras, L., Tsopelas, K., Giannopoulos, G., Sacharidis, D., Psaroudaki, E., Theologitis, N., Rontogiannis, D., Fotakis, D., & Emiris, I. (2023). Fairness Aware Counterfactuals for Subgroups. In Proceedings of the 37th Conference on Neural Information Processing Systems (NeurIPS 2023)._
6. _OWASP Foundation. (2016). OWASP Benchmark (Version 1.2) \[Computer software\]._ [_https://owasp.org/www-project-benchmark/_](https://owasp.org/www-project-benchmark/)
7. _Steenhoek, B., Gao, H., & Le, W. (2024). Dataflow analysis-inspired deep learning for efficient vulnerability detection. In Proceedings of the 46th International Conference on Software Engineering (pp. 1-13). <https://doi.org/10.1145/3597503.3623345>_

**Project Approval**

| **Research Committee use only** |     |     |     |
| --- |     |     |     | --- | --- |
| Decision reached: | Project approved |     | ![](data:image/x-wmf;base64,AQAJAAADowEAAAIAIwEAAAAABAAAAAMBCAAFAAAACwIAAAAABQAAAAwCEgATAAMAAAAeAAcAAAD8AgAA4ODgAAAABAAAAC0BAAAJAAAAHQYhAPAAEgATAAAAAAAEAAAALQEAAAkAAAAdBiEA8AASAAQAAAAPAAUAAAALAgAAAAAFAAAADAISABMABQAAAAEC4ODgAAUAAAAuAQAAAAAFAAAAAgEBAAAAHAAAAPsC8f8AAAAAAACQAQAAAAAAQAACQXJpYWwAZkEAAAAAEGsElfh/AAAAAAAAAAAAAHgVCn4EAAAALQEBAAUAAAAJAgAAAAAjAQAAQAkgAMwAAAAAAA0ADQACAAEAKAAAAA0AAAANAAAAAQAYAAAAAAAIAgAAAAAAAAAAAAAAAAAAAAAAAP///////////////////////////////////////////////////wCgoKDj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+P///8AoKCgaWlp////////////////////////////////////4+Pj////AKCgoGlpaf///////////////////////////////////+Pj4////wCgoKBpaWn////////////////////////////////////j4+P///8AoKCgaWlp////////////////////////////////////4+Pj////AKCgoGlpaf///////////////////////////////////+Pj4////wCgoKBpaWn////////////////////////////////////j4+P///8AoKCgaWlp////////////////////////////////////4+Pj////AKCgoGlpaf///////////////////////////////////+Pj4////wCgoKBpaWn////////////////////////////////////j4+P///8AoKCgaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlp4+Pj////AKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoP///wAEAAAAJwH//wMAAAAAAA==) |
| Project approved in principle |     | ![](data:image/x-wmf;base64,AQAJAAADowEAAAIAIwEAAAAABAAAAAMBCAAFAAAACwIAAAAABQAAAAwCEQATAAMAAAAeAAcAAAD8AgAA4ODgAAAABAAAAC0BAAAJAAAAHQYhAPAAEQATAAAAAAAEAAAALQEAAAkAAAAdBiEA8AARAAQAAAAPAAUAAAALAgAAAAAFAAAADAIRABMABQAAAAEC4ODgAAUAAAAuAQAAAAAFAAAAAgEBAAAAHAAAAPsC8f8AAAAAAACQAQAAAAAAQAACQXJpYWwAZlQAAAAAEGsElfh/AAAAAAAAAAAAAHgVCn4EAAAALQEBAAUAAAAJAgAAAAAjAQAAQAkgAMwAAAAAAA0ADQACAAEAKAAAAA0AAAANAAAAAQAYAAAAAAAIAgAAAAAAAAAAAAAAAAAAAAAAAP///////////////////////////////////////////////////wCgoKDj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+P///8AoKCgaWlp////////////////////////////////////4+Pj////AKCgoGlpaf///////////////////////////////////+Pj4////wCgoKBpaWn////////////////////////////////////j4+P///8AoKCgaWlp////////////////////////////////////4+Pj////AKCgoGlpaf///////////////////////////////////+Pj4////wCgoKBpaWn////////////////////////////////////j4+P///8AoKCgaWlp////////////////////////////////////4+Pj////AKCgoGlpaf///////////////////////////////////+Pj4////wCgoKBpaWn////////////////////////////////////j4+P///8AoKCgaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlp4+Pj////AKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoP///wAEAAAAJwH//wMAAAAAAA==) |
| Decision deferred |     | ![](data:image/x-wmf;base64,AQAJAAADowEAAAIAIwEAAAAABAAAAAMBCAAFAAAACwIAAAAABQAAAAwCEgATAAMAAAAeAAcAAAD8AgAA4ODgAAAABAAAAC0BAAAJAAAAHQYhAPAAEgATAAAAAAAEAAAALQEAAAkAAAAdBiEA8AASAAQAAAAPAAUAAAALAgAAAAAFAAAADAISABMABQAAAAEC4ODgAAUAAAAuAQAAAAAFAAAAAgEBAAAAHAAAAPsC8f8AAAAAAACQAQAAAAAAQAACQXJpYWwAZmQAAAAAEGsElfh/AAAAAAAAAAAAAHgVCn4EAAAALQEBAAUAAAAJAgAAAAAjAQAAQAkgAMwAAAAAAA0ADQACAAEAKAAAAA0AAAANAAAAAQAYAAAAAAAIAgAAAAAAAAAAAAAAAAAAAAAAAP///////////////////////////////////////////////////wCgoKDj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+P///8AoKCgaWlp////////////////////////////////////4+Pj////AKCgoGlpaf///////////////////////////////////+Pj4////wCgoKBpaWn////////////////////////////////////j4+P///8AoKCgaWlp////////////////////////////////////4+Pj////AKCgoGlpaf///////////////////////////////////+Pj4////wCgoKBpaWn////////////////////////////////////j4+P///8AoKCgaWlp////////////////////////////////////4+Pj////AKCgoGlpaf///////////////////////////////////+Pj4////wCgoKBpaWn////////////////////////////////////j4+P///8AoKCgaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlp4+Pj////AKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoP///wAEAAAAJwH//wMAAAAAAA==) |
| Project not approved |     | ![](data:image/x-wmf;base64,AQAJAAADowEAAAIAIwEAAAAABAAAAAMBCAAFAAAACwIAAAAABQAAAAwCEgATAAMAAAAeAAcAAAD8AgAA4ODgAAAABAAAAC0BAAAJAAAAHQYhAPAAEgATAAAAAAAEAAAALQEAAAkAAAAdBiEA8AASAAQAAAAPAAUAAAALAgAAAAAFAAAADAISABMABQAAAAEC4ODgAAUAAAAuAQAAAAAFAAAAAgEBAAAAHAAAAPsC8f8AAAAAAACQAQAAAAAAQAACQXJpYWwAZmAAAAAAEGsElfh/AAAAAAAAAAAAAHgVCn4EAAAALQEBAAUAAAAJAgAAAAAjAQAAQAkgAMwAAAAAAA0ADQACAAEAKAAAAA0AAAANAAAAAQAYAAAAAAAIAgAAAAAAAAAAAAAAAAAAAAAAAP///////////////////////////////////////////////////wCgoKDj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+P///8AoKCgaWlp////////////////////////////////////4+Pj////AKCgoGlpaf///////////////////////////////////+Pj4////wCgoKBpaWn////////////////////////////////////j4+P///8AoKCgaWlp////////////////////////////////////4+Pj////AKCgoGlpaf///////////////////////////////////+Pj4////wCgoKBpaWn////////////////////////////////////j4+P///8AoKCgaWlp////////////////////////////////////4+Pj////AKCgoGlpaf///////////////////////////////////+Pj4////wCgoKBpaWn////////////////////////////////////j4+P///8AoKCgaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlp4+Pj////AKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoP///wAEAAAAJwH//wMAAAAAAA==) |
| Project rejected |     | ![](data:image/x-wmf;base64,AQAJAAADowEAAAIAIwEAAAAABAAAAAMBCAAFAAAACwIAAAAABQAAAAwCEQATAAMAAAAeAAcAAAD8AgAA4ODgAAAABAAAAC0BAAAJAAAAHQYhAPAAEQATAAAAAAAEAAAALQEAAAkAAAAdBiEA8AARAAQAAAAPAAUAAAALAgAAAAAFAAAADAIRABMABQAAAAEC4ODgAAUAAAAuAQAAAAAFAAAAAgEBAAAAHAAAAPsC8f8AAAAAAACQAQAAAAAAQAACQXJpYWwAZlgAAAAAEGsElfh/AAAAAAAAAAAAAHgVCn4EAAAALQEBAAUAAAAJAgAAAAAjAQAAQAkgAMwAAAAAAA0ADQACAAEAKAAAAA0AAAANAAAAAQAYAAAAAAAIAgAAAAAAAAAAAAAAAAAAAAAAAP///////////////////////////////////////////////////wCgoKDj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+P///8AoKCgaWlp////////////////////////////////////4+Pj////AKCgoGlpaf///////////////////////////////////+Pj4////wCgoKBpaWn////////////////////////////////////j4+P///8AoKCgaWlp////////////////////////////////////4+Pj////AKCgoGlpaf///////////////////////////////////+Pj4////wCgoKBpaWn////////////////////////////////////j4+P///8AoKCgaWlp////////////////////////////////////4+Pj////AKCgoGlpaf///////////////////////////////////+Pj4////wCgoKBpaWn////////////////////////////////////j4+P///8AoKCgaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlp4+Pj////AKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoP///wAEAAAAJwH//wMAAAAAAA==) |
| Project reference number: Click here to enter text. |     |     |     |
| Name: Click here to enter text. |     | Date: Click here to enter a date. |     |
| Signature: |     |     |     |
| Details of any conditions upon which approval is dependant:<br><br>Click here to enter text. |     |     |     |
