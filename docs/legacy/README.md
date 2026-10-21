# Legacy: OnyxSec Streamlit prototype

`onyxsec_dossier.py` is the original OnyxSec code-audit prototype, kept for
historical reference only.

- It is **not** part of the NullVector runtime and is not deployed.
- It targets the hosted Groq API and expects an API key pasted into the UI.
- It uses the retired OnyxSec name throughout.

## Known defect (not fixed)

`render_vuln_card()` interpolates model-derived fields (`severity`, `owasp_id`,
`category`, and the finding body) into `st.markdown(..., unsafe_allow_html=True)`
without escaping. Model output therefore reaches an HTML sink, including inside a
CSS class attribute, which is an injection sink in the prototype's own UI.

It is left in place rather than patched because the file is retired; do not
reuse its rendering pattern in NullVector. The current runtime never renders
HTML from model output.
