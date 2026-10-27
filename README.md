# Sec Hub

Sec Hub는 로컬 저장소에 설치된 보안 검사기를 실행하고, 결과를 JSON, SARIF 2.1.0, 단일 HTML 보고서로 저장하는 Node.js CLI입니다. Node.js 22 이상과 내장 모듈만 사용합니다.

검사 대상 저장소의 스크립트를 자동 실행하거나 도구를 설치하지 않습니다. AI 검사기는 `--ai`와 명시적인 설정이 필요합니다. 코드 업로드 가능성이 있는 도구는 실행 전 각 도구의 정책과 설정을 확인하세요. Sec Hub는 자동 패치를 적용하지 않으며 하위 프로세스를 샌드박스라고 부르지 않습니다.

## 설치

```sh
cd outputs/sec-hub
npm install
node bin/sec-hub.mjs --help
```

`npm install`은 런타임 의존성을 추가하지 않습니다. 전역 명령이 필요하면 선택적으로 `npm link`를 실행할 수 있습니다. 기본 사용은 `node bin/sec-hub.mjs`입니다.

## 명령

CLI adapter는 다음 다섯 가지입니다: Google OSV Scanner (`osv`), NVIDIA SkillSpector (`skillspector`), OpenAI Codex Security (`codex-security`), Alibaba Open Code Review (`open-code-review`), OpenAI PHP2Shell Checker (`php2shell`). 사용 가능 여부와 필요한 자격 증명은 `doctor` 결과를 확인하세요.

설치 및 설정 상태 확인:

```sh
node bin/sec-hub.mjs doctor /path/to/repository
node bin/sec-hub.mjs doctor /path/to/repository --json
```

검사 실행. 기본 모드는 OSV Scanner와 정적 전용 SkillSpector를 사용 가능한 경우에 실행하며, `--tools`는 선택 도구를 지정합니다.

```sh
node bin/sec-hub.mjs scan /path/to/repository
node bin/sec-hub.mjs scan /path/to/repository --tools osv,skillspector
node bin/sec-hub.mjs scan /path/to/repository --ai --tools codex-security,open-code-review --config ./sec-hub.config.json
node bin/sec-hub.mjs scan /path/to/repository --url http://127.0.0.1:8080 --tools php2shell --out ./sec-hub-runs
node bin/sec-hub.mjs scan /path/to/repository --timeout 180 --out ./sec-hub-runs
```

URL 검사는 명시적으로 준 HTTP(S) 주소에만 요청합니다. `--timeout`은 초 단위입니다. 실행 결과 폴더에 `run.json`, `report.html`, `results.sarif`가 생성됩니다. 종료 코드는 정상 완료이며 finding 없음 `0`, finding 있음 `1`, 오류 또는 불완전한 실행 `2`입니다.

기존 데이터에서 보고서 재생성:

```sh
node bin/sec-hub.mjs report ./sec-hub-runs/RUN_ID
node bin/sec-hub.mjs report ./sec-hub-runs/RUN_ID/run.json
```

브리지 가이드와 import 계약 내보내기, 결과 가져오기:

```sh
node bin/sec-hub.mjs bridge cloudflare --out ./cloudflare-handoff
node bin/sec-hub.mjs bridge anthropic --out ./anthropic-handoff
node bin/sec-hub.mjs import cloudflare ./cloudflare-handoff/findings.json --target /path/to/repository --out ./sec-hub-import
node bin/sec-hub.mjs import anthropic ./anthropic-handoff/findings.json --target /path/to/repository --out ./sec-hub-import
```

가져온 결과의 도구 상태는 `imported`이며 로컬에서 실행한 결과가 아닙니다. 비어 있거나 알 수 없는 데이터 모양은 안전한 무결과로 해석하지 않고 거부합니다. Cloudflare는 공식 native schema의 `confirmed`, `needs_validation`, `rejected`를 지원합니다. `rejected`는 imported 기록의 건수로 보존하지만 취약점 결과로 세지 않습니다. Anthropic은 문서화된 Sec Hub JSON 계약만 지원합니다. upstream 고유 출력 형식은 지원한다고 주장하지 않습니다.

## 도구 설정

모든 다섯 adapter의 설정 예시는 [examples/sec-hub.config.json](examples/sec-hub.config.json)에 있습니다. 파일은 설치된 실행 파일 이름을 사용하며, PHP 검사기 스크립트 경로는 각자 clone한 절대 경로로 바꿔야 합니다. 예시에는 자격 증명이 없습니다.

설정 파일은 `--config`로 전달해야 읽습니다. 검사 대상 저장소의 설정 파일을 자동으로 읽지 않습니다. 각 항목은 실행 파일과 argv 접두사로 지정합니다. shell command 문자열은 지원하지 않습니다.

```json
{
  "tools": {
    "osv": { "command": "osv-scanner", "args": [] },
    "skillspector": { "command": "skillspector", "args": [] },
    "codex-security": { "command": "cs", "args": [] },
    "open-code-review": { "command": "ocr", "args": [] },
    "php2shell": { "command": "node", "args": ["/absolute/path/to/php2shell-checker/skills/phpcheck-url/scripts/phpcheck.js"] }
  }
}
```

PHP 검사기는 Node 실행 파일 뒤에 스크립트 경로를 설정합니다. AI 도구는 동일하게 실행 파일과 인자를 설정하고 `--ai`를 함께 전달합니다. 자격 증명은 도구가 요구하는 환경에서 직접 제공합니다. 설정 파일과 상속된 환경 변수는 보고서에 기록되지 않습니다.

## 결과 해석

HTML 보고서는 각 도구의 selected/completed/skipped/failed/imported 상태, 실행 범위, 실패 사유, 미실행으로 인한 범위 제한을 함께 표시합니다. finding의 `candidate`, `reported`, `confirmed` 출처 상태를 구분합니다. 모든 검사가 완료되어 finding이 0건이어도 취약점이 없다는 증명은 아닙니다. SARIF에서 `unknown` 심각도는 `level: none`과 `properties.severity: unknown`으로 유지됩니다.

OSV의 취약점 DB 조회와 SkillSpector의 선택적 advisory 조회는 네트워크를 사용할 수 있으므로 완전한 오프라인 검사가 아닙니다. Codex Security 및 Open Code Review는 설정된 서비스에 코드를 업로드할 수 있습니다. PHP2Shell Checker는 지정 URL의 헤더/버전 휴리스틱 검사입니다. 도구 출력의 경고와 네트워크 동작은 해당 upstream 문서를 확인하세요. 비밀값 탐지는 일반적인 비밀 탐지기가 아닙니다.

## 외부 연결

- [Cloudflare Security Audit Skill](https://github.com/cloudflare/security-audit-skill) — 실행은 별도로 수행하고 결과를 검토해 Sec Hub 브리지로 가져옵니다. 공식 `skills/security-audit/report-schema.json` 형식을 지원합니다.
- [Anthropic Defending Code Reference Harness](https://github.com/anthropics/defending-code-reference-harness) — 저장소 README에서 유지 관리되지 않는다고 설명하며 라이선스 메타데이터는 `NOASSERTION`입니다. 구현물을 Sec Hub에 포함하지 않습니다. 결과는 Sec Hub 계약 형식으로 변환해야 합니다.

양쪽 브리지의 가져오기용 스키마와 예시는 `node bin/sec-hub.mjs bridge <provider> --out <directory>`로 내보낼 수 있습니다. 이 저장소의 예시는 [Cloudflare](examples/cloudflare-bridge.json), [Anthropic](examples/anthropic-bridge.json)입니다.

## 개발

저장소의 자동화 테스트는 실행 인자, 파서, 정규화, 보고서와 가져오기 계약을 검사합니다. 모의/fixture 테스트 통과만으로 upstream 보안 검사기가 실제로 실행됐다고 볼 수 없습니다. 실제 upstream 실행 검증 여부는 실행 기록으로 별도 확인해야 합니다.

```sh
node --test
```

## 이번 빌드의 검증 결과

자동 테스트 58개를 통과했고, 실제 OSV·정적 SkillSpector·PHP 검사기로 통제된 데이터에서 총 10건을 수집했습니다. [실제 HTML 보고서](verification/final-scan/report.html), [검증 기록](verification/VALIDATION.md), [보안 재검토 기록](verification/REVIEW.md)을 확인할 수 있습니다. Codex Security/Open Code Review의 인증된 모델 호출과 Cloudflare/Anthropic의 실제 에이전트 감사는 실행하지 않았습니다. 이 환경에서 준비한 세 도구의 경로는 `verification/tools.config.json`에 있으며, 다른 기기에서는 경로를 바꿔야 합니다.
