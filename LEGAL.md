# Sentinel CLI — Legal Information

## Privacy Policy

### 1. Data Collection

Sentinel CLI runs entirely on your local machine. We do not operate servers, collect telemetry, or transmit any data to us.

**The software collects and stores locally:**

| Data | Where | Purpose | Retention |
|------|-------|---------|-----------|
| API keys (Gemini, Claude, OpenAI, Ollama) | `~/.sentinel/auth.json` — encrypted file | Authenticate with AI providers | Until user runs `/auth remove` or deletes file |
| Scan results & findings | `~/.sentinel/threat.db` — local SQLite | Threat intelligence correlation | Until user deletes the file |
| Custom rules & configuration | `~/.sentinel/rules.json`, config files | User preferences persistence | Until user deletes the file |
| Conversation history | In-memory during session | AI context for multi-turn chat | Lost on session end |
| CLI 1 classified files index | Local file cache | Cross-CLI deduplication | Until user runs `/cli1-import` again |
| Permission cache | In-memory | Avoid re-prompting for approved tools | Until user runs `/trust clear` or exits |

### 2. Third-Party Data Processing

When you use Sentinel Oracle Core with a third-party AI provider, your prompts and file contents are sent to that provider's API:

- **Google Gemini**: Prompts and tool outputs are processed by Google. See [Google Privacy Policy](https://policies.google.com/privacy).
- **Anthropic Claude**: Prompts and tool outputs are processed by Anthropic. See [Anthropic Privacy Policy](https://www.anthropic.com/privacy).
- **OpenAI**: Prompts and tool outputs are processed by OpenAI. See [OpenAI Privacy Policy](https://openai.com/privacy/).
- **Ollama (local)**: No data leaves your machine.

When you use SecuriGit / `gh` tools, authentication and API requests go through GitHub's infrastructure. See [GitHub Privacy Statement](https://docs.github.com/en/site-policy/privacy-policies/github-privacy-statement).

### 3. No Telemetry

Sentinel CLI does **not**:
- Collect usage statistics
- Send crash reports
- Track feature usage
- Phone home to any server
- Display advertisements

### 4. Data Security

- API keys are stored with filesystem permissions `0o600` (owner read/write only).
- The threat database is a local SQLite file with no network exposure.
- No data is ever transmitted to Sentinel Security or any third party except the AI provider you explicitly configure.

### 5. Data Deletion

To delete all local data:

```bash
rm -rf ~/.sentinel
```

To delete only API keys:

```bash
sentinel oracle auth remove <provider>
```

or run `/auth remove` inside an Oracle session.

---

## Terms and Conditions

### 1. License

Sentinel CLI is licensed under the **Business Source License 1.1 (BUSSL-1.1)**.

- **Licensed Work**: The Sentinel CLI software (all source code, documentation, and associated files).
- **Change Date**: 2030-05-20.
- **Change License**: GNU General Public License v2.0 (GPL-2.0).

During the BUSSL-1.1 period, you may:
- Use the software for any lawful purpose.
- Modify the software for your own use.
- Distribute the software internally within your organization.

You may **not**:
- Offer the software or modified versions as a commercial service (SaaS, hosting, managed security).
- Sell the software or charge for access to it.
- Remove or alter license notices.

After the Change Date (2030-05-20), the software becomes GPL-2.0 and all GPL-2.0 terms apply.

### 2. Acceptable Use

You agree not to use Sentinel CLI for:
- Violating any applicable law or regulation.
- Scanning systems you do not own or have explicit permission to test.
- Storing or processing illegal content.
- Circumventing security measures of any system.
- Any activity that violates the acceptable use policies of the AI providers or GitHub.

### 3. Disclaimer of Warranties

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

### 4. Limitation of Liability

IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, CONSEQUENTIAL, OR INCIDENTAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) ARISING OUT OF THE USE OR INABILITY TO USE THE SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.

### 5. Security Scanner Disclaimer

Sentinel CLI's SAST scanner and security tools are **aid** tools, not replacements for professional security audits. A clean scan does not guarantee the absence of vulnerabilities. False positives and false negatives may occur. Always validate findings manually.

### 6. Third-Party Services

Your use of AI providers (Google, Anthropic, OpenAI) and GitHub through Sentinel CLI is subject to their respective terms of service and privacy policies. Sentinel Security is not responsible for the data handling practices of these third parties.

### 7. Termination

Your rights under this license terminate automatically if you violate any of its terms.

---

## Compliance

### Data Retention Summary

| Data Type | Location | Retention Period | Deletion Method |
|-----------|----------|-----------------|-----------------|
| API keys | `~/.sentinel/auth.json` | Until removed | `/auth remove <provider>` or delete file |
| Scan findings | `~/.sentinel/threat.db` | Until deleted | Delete `~/.sentinel/` |
| Rules & config | `~/.sentinel/` JSON files | Until deleted | Delete individual files |
| Session history | In-memory | Session duration | Automatic on exit |
| Permission cache | In-memory | Session duration | `/trust clear` or exit |

### GDPR Compliance

If you are in the European Economic Area (EEA):
- **Data controller**: You are the data controller. Sentinel Security does not process your personal data.
- **Data processor**: AI providers you configure act as data processors. Review their GDPR compliance documentation.
- **Right to erasure**: Delete `~/.sentinel/` to erase all locally stored data.
- **Data portability**: Use `/export config` to export your configuration in JSON format.
- **No profiling**: The software does not perform automated profiling or decision-making.

### SOC 2 / ISO 27001

Sentinel CLI is a local tool and does not provide cloud services. Compliance with SOC 2, ISO 27001, or similar frameworks is your responsibility when deploying the tool within your organization. The software's architecture supports compliance by:
- Keeping all data local (no unauthorized transmission).
- Using filesystem-level permissions for sensitive files.
- Providing clear audit trails via `/audit` and report exports.

---

## Intellectual Property

### Ownership

- **Sentinel CLI code**: Copyright © 2025-2026 Sentinel Security. All rights reserved under the BUSSL-1.1 license.
- **Sentinel and SecuriGit**: "Sentinel", "Sentinel Oracle Core", and "SecuriGit" are trademarks of Sentinel Security.
- **Your code**: Sentinel CLI does not claim ownership of any code you scan, analyze, or process with the tool. Your code remains your intellectual property.
- **AI provider output**: Content generated by AI providers is subject to the terms of those providers.

### Third-Party Components

Sentinel CLI uses open-source packages. Their licenses are listed in `package.json` and the `node_modules/` directory. Notable dependencies:
- **Commander.js** — MIT License
- **Picocolors** — ISC License
- **Better-sqlite3** — MIT License
- **@google/generative-ai** — Apache 2.0
- All other dependencies retain their original licenses.

### Contributions

By contributing to Sentinel CLI (via pull requests, issues, or otherwise), you agree that your contributions are licensed under the same BUSSL-1.1 license and that you grant Sentinel Security a perpetual, worldwide, non-exclusive, royalty-free license to use your contributions.

---

*Last updated: 2026-06-01*
*Sentinel CLI v4.0.0*
