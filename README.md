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

AI 검사에만 적용할 인증 방식·모델·실행 예산은 선택적인 `scanOptions`로 지정할 수 있습니다. [예산을 제한한 다섯 도구 설정 예시](examples/ai-tools.config.json)는 upstream 로그인 저장소를 사용하는 예시이며 자격 증명을 포함하지 않습니다. `args`는 계속 실행 파일 접두사이며, `scanOptions`는 `scan` 뒤에만 추가됩니다. 버전 확인과 Codex `export`에는 전달하지 않습니다. `--ai`는 여전히 필수입니다.

Codex 옵션은 `auth` (`chatgpt`, `api-key`, `auto`), `model` (비어 있지 않은 문자열), `effort` (`low`, `medium`, `high`, `xhigh`), `maxCost`와 `maxTimeMinutes` (양수)입니다. OCR 옵션은 `provider`, `model` (비어 있지 않은 문자열), `maxTokensBudget`, `concurrency`, `timeoutMinutes` (양의 정수), `noPlan`, `noDedup`, `noSummary` (boolean)입니다. 알 수 없는 옵션과 패치·출력 경로 덮어쓰기는 거부합니다. 네이티브 예산은 upstream 정책에 따른 제한이며, Sec Hub의 `--timeout`도 별도로 적용됩니다.

OCR은 다음 파일의 예상 토큰을 예산에 미리 예약하므로 실제 사용량이 한도보다 낮아도 파일 검토를 건너뛸 수 있습니다. 이 합성 fixture에서는 20,000 토큰 예산이 `server.mjs` 배치를 막았으므로 예시는 40,000을 사용합니다. `budget_exceeded`나 검토 제한 경고가 있으면 finding이 0건이어도 완료로 처리하지 않습니다.

인증된 다섯 CLI를 재검증하려면 upstream의 공식 로그인 명령으로 먼저 로그인하고, 설치 경로를 바꾼 명시적 설정과 새 절대 출력 경로를 전달합니다. 이 명령은 AI 서비스를 실제 호출합니다.

```sh
node scripts/live-verify-five.mjs --config /absolute/ai-tools.config.json --out /absolute/new-verification-run
```

필요하면 `--runtime /absolute/node`로 Node 22 이상 실행 파일을 지정할 수 있습니다. helper는 `work/live-five-target-*`에 안전한 합성 소스와 오래된 의존성 메타데이터를 복사하고, localhost PHP 응답 헤더를 검사하며, 대상 소스를 설치하거나 실행하지 않습니다. 다섯 도구를 명시적으로 선택하고 각 도구에 600초 제한을 적용합니다. 완료 상태·네이티브 출력·보고서 재생성·SARIF·파일 SHA-256을 기록합니다. 실패와 부분 결과도 보존하며, 다섯 도구 모두 완료해야 helper가 성공합니다. OCR의 새 세션 메타데이터는 추가 파일로 기록하고, 기존 소스가 수정되면 검증 실패로 처리합니다. Git 내부 메타데이터는 해시 대상에서 제외합니다. 테스트에서 사용하는 controlled CLI는 실제 인증 호출의 증거가 아닙니다.

검증 과정에서 OCR만 재시도한 두 실행을 합칠 때는 `scripts/combine-verified-runs.mjs --original /absolute/initial-run --retry /absolute/ocr-retry --out /absolute/new-combined-run`을 사용할 수 있습니다. 이 helper는 같은 경로·revision과 원래 대상의 실행 전·후·현재 SHA-256, 보존된 네이티브 결과 및 원본 아티팩트 해시를 확인합니다. 초기 실행의 네 도구 완료와 OCR 실패, OCR만 선택한 성공 재시도가 필요합니다. 합친 보고서는 `aggregate` 출처와 두 실행 ID, 원래 실패 이력을 명시하며 두 실행을 한 번의 검사로 표시하지 않습니다. 원래 실행 폴더는 수정하지 않습니다.

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

0.1.1은 자동 테스트 68개를 통과했고, Codex Security와 Open Code Review의 ChatGPT 인증을 포함한 실제 5개 CLI 검사에서 검증용 코드의 결과 13건을 수집했습니다. [통합 HTML 보고서](verification/authenticated-five-combined/report.html)와 [인증·실행 검증 기록](verification/AUTHENTICATED-VALIDATION.md)을 확인할 수 있습니다. 최초 실행과 OCR 예산 조정 재실행의 출처를 보존했으며, 동일 코드의 해시와 원본 결과를 검증해 결합했습니다. 다섯 도구의 실행 경로와 모델·제한 설정은 `verification/authenticated-tools.config.json`에 있습니다. 인증 정보는 패키지에 포함하지 않으며, 다른 기기에서는 도구 설치·로그인과 경로 변경이 필요합니다. Cloudflare/Anthropic은 계속 실행 안내와 결과 가져오기를 제공합니다.
