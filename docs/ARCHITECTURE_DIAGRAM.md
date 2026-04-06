# SecureAgent Architecture Diagram

```mermaid
flowchart TD
    A[User or Browser Agent Goal] --> B[SecureAgent Extension]
    B --> C[Action Interception]
    B --> D[Page Context Collection]
    D --> E[Backend Scan Pipeline]
    E --> F[Domain Intelligence]
    E --> G[ML Content Scoring]
    E --> H[LLM Intent Reasoning]
    E --> I[UI Deception Analysis]
    E --> J[Obfuscation Analysis]
    E --> K[Browser Runtime Signals]
    F --> L[Risk Scoring Engine]
    G --> L
    H --> L
    I --> L
    J --> L
    K --> L
    L --> M[Policy Engine]
    M --> N[Action Mediator]
    N --> O[Allow / Confirm / Block]
    O --> P[Protected Agent Executor]
    O --> Q[Dashboard + Audit Trail]
    P --> B
    Q --> R[Benchmark Reports]
```

## Notes

- The protected agent executor loops through page perception, planning, scanning, mediation, execution, and replanning.
- Browser runtime inspection is preferred when Selenium/Chrome is available and falls back safely to HTTP parsing.
- Benchmark and stress outputs are exported into `benchmark-results/latest/` for demo and submission use.
