# Sec Hub

> 0.2.3은 Windows 하위 프로세스 종료 경계 #31, trusted ancestor 경계 #40, Darwin ACL reader native helper를 포함합니다. 배포 tarball은 빈 private npm 프로젝트에 오프라인 설치해 확인했습니다. 설치된 CLI를 통제된 fixture에서 OSV Scanner, 정적 SkillSpector, PHP2Shell checker로 실행해 총 10개 finding을 기록했고, 대상 파일은 바뀌지 않았습니다. 기존 read-only dashboard도 기능별로 확인했습니다. Anthropic workflow는 보류하며, 이 검증은 Sec Hub 자체나 7개 도구 전체의 보안 재감사가 아닙니다. [0.2.3 패키지·검증 보고서](verification/release-0.2.3/REPORT.md).

> 0.2.2는 Open Code Review 0.2.1 재검사의 고위험 #9·#12와 중간 심각도 19건을 수정한 안정화 버전입니다. 중간 후보 #13은 기존 pinned 공식 검증기가 이미 차단해 반증됐습니다. 새 테스트 57개를 포함해 Node 24 전체 **385/385 통과**, 명세·독립 품질 검토도 통과했습니다. [0.2.2 패키지](releases/sec-hub-local-0.2.2.tgz), [22건 판정·수정·실행 검증 보고서](verification/release-0.2.2/REPORT.md), [전체 테스트 로그](verification/release-0.2.2/evidence/full-suite-node24.log)를 확인하세요.

기존 0.2.2 release archive는 이전 source checkout의 고위험 #38(가림 실패 후 원문 잔존)·#41(POSIX 경로 검증 우회) 수정과 검증을 포함합니다. 0.2.1 배포 파일과 44개 native 후보의 [원본 재검사 기록](verification/ocr-0.2.1-assessment/REPORT.md), [이전 두 수정 기록](verification/high2-remediation/REPORT.md)은 보존되어 있습니다. 0.2.2 archive는 그대로이며 #31/#40 후속 수정은 그 패키지에 포함되지 않습니다.

메타데이터 버전 변경 전 #31/#40 런타임 회귀 검증에서 Node 24 전체 suite는 424개 중 423 pass, 0 fail, 1 native Windows skip으로 통과했습니다. 이 결과는 0.2.3 메타데이터 변경 후 전체 suite를 다시 실행한 결과가 아닙니다. #31의 `taskkill /T /F`는 Darwin에서 OS 경계 모의로 확인했으며 실제 Windows 실행은 검증하지 않았습니다. #40은 root와 현재 effective UID를 trusted ancestor로 간주하는 권한 정책을 강제하며, 같은 UID의 악의적 process가 일으키는 directory-swap은 여전히 범위 밖입니다. [#31/#40 로컬 수정·검증 보고서](verification/high31-40-remediation/REPORT.md).

이 보안 경계에는 배포 영향이 있습니다. Windows에서는 safe filesystem helper가 필요한 report write뿐 아니라 source/skill-root read도 fail closed합니다. macOS에서는 shared writable ancestor(고정 sticky `/tmp` 포함)와 ALLOW/unknown ACL을 거부하고, ancestor별 ACL 확인이 startup·source 검사·보고서 저장 시간을 늘립니다. Linux의 mode/sticky 정책은 native Linux에서 실행 검증하지 않았습니다. Darwin ACL helper는 macOS arm64에서 실행했고 universal x86_64 slice는 별도로 native 실행하지 않았습니다.

기존 Cloudflare 실행은 정적 source-only quick coverage로, 두 개의 미확정 후보와 unknown 심각도를 기록했습니다. SARIF 스키마·인증정보 패턴 검사와 HTML·증거 링크 QA를 완료했습니다. 이는 7개 검증 완료나 동적 악용 확인을 뜻하지 않습니다. 활성화된 1회 후속 작업은 2026년 10월 29일 오전 6:10(뉴욕 시간)에 Anthropic native canary, 정적 검사, 최종 집계만 수행합니다.

Sec Hub는 로컬 저장소에 설치된 보안 검사기를 실행하고, 결과를 JSON, SARIF 2.1.0, 단일 HTML 보고서로 저장하는 Node.js CLI입니다. Node.js 22 이상과 내장 모듈만 사용합니다.

검사 대상 저장소의 스크립트를 자동 실행하거나 도구를 설치하지 않습니다. AI 검사기는 `--ai`와 명시적인 설정이 필요합니다. 코드 업로드 가능성이 있는 도구는 실행 전 각 도구의 정책과 설정을 확인하세요. Sec Hub는 자동 패치를 적용하지 않으며 하위 프로세스를 샌드박스라고 부르지 않습니다.

## 설치

```sh
cd outputs/sec-hub
npm install
node bin/sec-hub.mjs --help
```

`npm install`은 런타임 의존성을 추가하지 않습니다. 전역 명령이 필요하면 선택적으로 `npm link`를 실행할 수 있습니다. 기본 사용은 `node bin/sec-hub.mjs`입니다.

0.2.3 패키지에는 CLI, 런타임, 예시와 README가 포함됩니다. `scripts/` 저장소 유지 관리 도구는 저장소 checkout에서만 사용할 수 있으며 설치 패키지에서는 제외됩니다. `src/native/` 아래 Darwin ACL reader binary, C source와 maintainer build script는 포함되며, build script는 provenance/rebuild 용도이고 CLI runtime에서 실행하거나 컴파일러를 호출하지 않습니다. 기존 0.2.2 release archive는 이 후속 helper를 포함하지 않습니다. 실행 증거는 저장소의 `verification/`에 남습니다.

## 명령

CLI adapter 다섯 가지와 공식 agent workflow 두 가지를 지원합니다. CLI adapter: Google OSV Scanner (`osv`), NVIDIA SkillSpector (`skillspector`), OpenAI Codex Security (`codex-security`), Alibaba Open Code Review (`open-code-review`), OpenAI PHP2Shell Checker (`php2shell`). 공식 agent workflow는 Cloudflare Security Audit (`cloudflare`)와 Anthropic `/vuln-scan` (`anthropic`)입니다. 사용 가능 여부와 필요한 자격 증명은 `doctor` 결과를 확인하세요. `doctor`는 중복 없는 일곱 ID를 반환하고 두 agent의 수동 import 지원은 capability로 표시합니다.

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

저장된 두 실행의 비교는 실행 중인 검사기나 인증 정보를 사용하지 않습니다. 각 입력은 이름과 관계없이 v1 저장 실행 JSON 파일이거나, `run.json`을 포함한 실행 디렉터리여야 합니다.

```sh
node bin/sec-hub.mjs compare ./baseline-run ./current-run
node bin/sec-hub.mjs compare ./baseline-run/run.json ./current-run --fail-on critical --out ./comparison-report
```

비교 결과 전체가 stdout에 키 순서가 정해진 JSON으로 출력됩니다. `--out`을 주면 같은 비교를 `comparison.json`과 `comparison.html`로 새 디렉터리에 저장합니다. 출력 폴더는 비어 있어야 하며 입력 실행과 겹칠 수 없습니다. 파일 해시와 읽은 `run.json` 경로가 입력 출처로 포함됩니다. 진단은 stderr에 기록됩니다.

`--fail-on` 기본값은 `high`이며 허용 값은 `critical`, `high`, `medium`, `low`, `info`, `any`, `none`입니다. 게이트는 새로 관측된 결과와 심각도가 올라간 결과만 평가합니다. 선택한 기준을 만족하는 새 결과가 있으면 종료 코드 1이고, 관련 `unknown` 심각도 또는 불완전한 비교 범위가 있으면 판단 불가인 2입니다. `any`는 심각도에 관계없이 새 결과를 차단하며, `none`은 finding 게이트를 끄지만 불완전한 범위의 종료 코드 2는 유지합니다. 모든 비교 항목을 JSON과 HTML에 포함합니다.

`new`는 기준 실행에서 보이지 않았다는 뜻이지 코드에 새로 도입되었다는 증명은 아닙니다. `candidate`와 `reported` 출처도 그대로 유지하며 `confirmed`로 승격하지 않습니다. 비교 가능한 검사 범위에서 확인 가능한 결과가 현재 실행에 없으면 `resolved`로 분류합니다. 이는 패치나 수정 확인이 아닙니다. 해당 검사가 누락·실패·부분 범위이거나 identity가 너무 약해 결과의 부재를 판단할 수 없으면 `unobserved`로 표시하고 비교를 불완전하게 처리합니다. 기존 `existing` 고심각도 결과는 new-only 게이트를 통과하며, 낮은 심각도에서 높은 심각도로 바뀐 항목은 `regressed`로 평가합니다.

두 실행은 같은 절대 대상 경로를 가리켜야 합니다. 저장된 revision이 다르면 각각 표시하며 비교를 허용합니다. 의존성 identity는 정확한 package/version과 주 식별자를 사용하므로 alias 변경은 새 결과와 사라진 결과로 나뉠 수 있습니다. fallback line identity는 줄 이동을 같은 취약점으로 추측하지 않으며 별도의 새 항목과 미관측 항목을 만들 수 있습니다. 중복 발생 수는 유지됩니다.

CI 비교 게이트는 OSV 단독 실행을 기본 프로필로 사용할 수 있습니다. 대상 저장소 루트에 `SKILL.md`가 있는 경우에만 `skillspector`를 추가하세요. 완료된 OSV와 SkillSpector 검사는 대상 범위에 맞춰 비교할 수 있습니다. Cloudflare quick profile은 항상 부분 범위이며 PHP endpoint 범위도 이력만으로 확인할 수 없어, 두 경우 모두 비교 게이트는 종료 코드 2를 반환합니다. 선택하지 않은 도구, 실패한 검사, 가져온 데이터, 누락된 도구 또는 알려지지 않은 검사 계약도 완전한 범위로 간주하지 않습니다. 그러므로 6개 도구 aggregate와 7개 통합 중 Anthropic이 보류된 결과는 성공적인 새 7개 전체 게이트로 처리되지 않습니다.

저장된 실행과 비교를 읽기 전용 로컬 대시보드에서 확인하려면 직접 선택한 실행 루트의 절대 경로를 지정합니다.

```sh
node bin/sec-hub.mjs serve --runs /absolute/path/to/sec-hub-runs
```

기본 포트 `0`은 운영체제가 사용 가능한 포트를 고르게 합니다. 출력된 `127.0.0.1` URL을 브라우저에서 직접 여세요. `--port`에는 기본값 외에 0–65535의 10진수 포트를 지정할 수 있습니다. 서버는 loopback에만 바인딩하며 브라우저는 같은 loopback origin으로만 API를 호출합니다. 인증은 제공하지 않으므로 공개 호스팅이나 신뢰할 수 없는 로컬 사용자로부터의 격리를 의미하지 않습니다.

대시보드는 루트의 `run.json`, `comparison.json`과 바로 아래 각 실행 디렉터리의 같은 이름 파일만 시작 시 한 번 읽습니다. 하위 트리를 재귀 탐색하지 않고 `raw/`, 원본 소스 또는 저장된 경로를 따라가지 않습니다. 파일을 추가한 뒤에는 서버를 재시작해야 합니다. 디렉터리 항목 512개, artifact 128개, artifact당 JSON 20 MiB, 전체 입력 64 MiB 등 용량 제한에 걸리면 화면에 잘림 또는 제한 안내가 표시됩니다. 대시보드는 저장된 HTML 보고서를 제공하지 않습니다.

실행 완료는 “안전 확인”이나 취약점 부재를 뜻하지 않습니다. 가져온 결과는 “가져온 결과 · 로컬 실행 아님”으로, 저장된 비교는 “저장된 비교 · 원본 검사 재검증 안 함”으로 표시합니다. 후보 결과를 확정 결과로 승격하지 않고, `resolved`도 수정 확인으로 표현하지 않습니다. 브라우저의 비교는 기존 비교 엔진을 메모리에서 실행하며 `comparison.json`이나 HTML 보고서를 쓰지 않습니다. 비교 게이트 0은 완전한 비교에서 선택한 기준을 통과, 1은 완전한 비교에서 위반, 2는 불완전하거나 판단할 수 없음을 나타냅니다. 게이트 결과는 응답 데이터이며 서버 종료 코드에는 영향을 주지 않습니다. Ctrl+C 또는 SIGTERM으로 서버를 종료합니다.

브리지 가이드와 import 계약 내보내기, 결과 가져오기:

```sh
node bin/sec-hub.mjs bridge cloudflare --out ./cloudflare-handoff
node bin/sec-hub.mjs bridge anthropic --out ./anthropic-handoff
node bin/sec-hub.mjs import cloudflare ./cloudflare-handoff/findings.json --target /path/to/repository --out ./sec-hub-import
node bin/sec-hub.mjs import anthropic ./anthropic-handoff/findings.json --target /path/to/repository --out ./sec-hub-import
```

이 수동 bridge/import 명령은 실제 agent 실행과 별도로 계속 지원합니다. 가져온 결과의 도구 상태는 `imported`이며 로컬에서 실행한 결과가 아닙니다. 비어 있거나 알 수 없는 데이터 모양은 안전한 무결과로 해석하지 않고 거부합니다. Cloudflare는 공식 native schema의 `confirmed`, `needs_validation`, `rejected`를 지원합니다. `rejected`는 imported 기록의 건수로 보존하지만 취약점 결과로 세지 않습니다. Anthropic은 문서화된 Sec Hub JSON 계약만 지원합니다. upstream 고유 출력 형식은 지원한다고 주장하지 않습니다.

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

아래 `scripts/` 유지 관리 명령은 저장소 checkout에서만 실행할 수 있습니다. 설치 패키지에는 `scripts/`와 해당 테스트 helper 및 fixture가 포함되지 않습니다. 인증된 다섯 CLI를 재검증하려면 upstream의 공식 로그인 명령으로 먼저 로그인하고, 설치 경로를 바꾼 명시적 설정과 새 절대 출력 경로를 전달합니다. 이 명령은 AI 서비스를 실제 호출합니다.

```sh
node scripts/live-verify-five.mjs --config /absolute/ai-tools.config.json --out /absolute/new-verification-run
```

필요하면 `--runtime /absolute/node`로 Node 22 이상 실행 파일을 지정할 수 있습니다. helper는 `work/live-five-target-*`에 안전한 합성 소스와 오래된 의존성 메타데이터를 복사하고, localhost PHP 응답 헤더를 검사하며, 대상 소스를 설치하거나 실행하지 않습니다. 다섯 도구를 명시적으로 선택하고 각 도구에 600초 제한을 적용합니다. 완료 상태·네이티브 출력·보고서 재생성·SARIF·파일 SHA-256을 기록합니다. 실패와 부분 결과도 보존하며, 다섯 도구 모두 완료해야 helper가 성공합니다. OCR의 새 세션 메타데이터는 추가 파일로 기록하고, 기존 소스가 수정되면 검증 실패로 처리합니다. Git 내부 메타데이터는 해시 대상에서 제외합니다. 테스트에서 사용하는 controlled CLI는 실제 인증 호출의 증거가 아닙니다.

검증 과정에서 OCR만 재시도한 두 실행을 합칠 때는 `scripts/combine-verified-runs.mjs --original /absolute/initial-run --retry /absolute/ocr-retry --out /absolute/new-combined-run`을 사용할 수 있습니다. 이 helper는 같은 경로·revision과 원래 대상의 실행 전·후·현재 SHA-256, 보존된 네이티브 결과 및 원본 아티팩트 해시를 확인합니다. 초기 실행의 네 도구 완료와 OCR 실패, OCR만 선택한 성공 재시도가 필요합니다. 합친 보고서는 `aggregate` 출처와 두 실행 ID, 원래 실패 이력을 명시하며 두 실행을 한 번의 검사로 표시하지 않습니다. 원래 실행 폴더는 수정하지 않습니다.

## 공식 security skill 실행

[일곱 도구 설정 예시](examples/seven-tools.config.json)의 실행 파일, 공식 checkout, private workRoot 절대 경로를 로컬 환경에 맞게 바꾸세요. 기존 기본 선택은 유지됩니다. 새 두 workflow는 비용 발생을 명확히 선택하도록 반드시 `--tools cloudflare,anthropic` 또는 일곱 ID 전체로 지정해야 합니다. `--ai`만 추가하면 기존 CLI 선택만 확장됩니다.

```sh
node bin/sec-hub.mjs scan /path/to/repository --ai --tools cloudflare,anthropic --config /absolute/seven-tools.config.json --timeout 1200 --out /absolute/new-native-run
```

`agentOptions`는 allowlist입니다. 공통 옵션은 `skillRoot`와 `workRoot` (절대 경로), `revision` (공식 pin 40자리 SHA), `model`입니다. Cloudflare는 `strategy` (`native-collab|supervised-codex-workers`, 생략 시 기존 `native-collab`), `effort` (`low|medium|high|xhigh`), `profile: "quick"`, `maxAgents` (기본 10; `native-collab`은 7 이상, `supervised-codex-workers`는 실행 전 최소 8 필요: recon 4 + planner 1 + hunter 1 + critic 1 + verifier 예약 1)을 지원합니다. Anthropic은 `maxTurns` (양의 정수, 기본 30), `maxBudgetUsd` (유한한 양수, 기본 3), `mode: "vuln-scan"`, `single: true`, `noScore: true`를 지원합니다. 임의 prompt, patch 설정, 비밀값 설정 및 알 수 없는 옵션은 거부합니다. `command`와 `args`는 기존과 같이 실행 파일과 argv 접두사입니다. upstream CLI의 로그인 상태를 사용하며 Sec Hub는 credential 파일을 읽거나 도구를 설치하지 않습니다.

Cloudflare는 pin `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8`의 agent-neutral security-audit skill을 Codex CLI로 실행합니다. 기존 `native-collab`은 실제 native spawn/wait 증거를 요구합니다. 명시적으로 선택하는 `supervised-codex-workers`는 trusted supervisor가 서로 독립적인 read-only Codex 프로세스를 실행하고, 4개 recon·planner·hunter wave·최종 critic·fresh verifier 및 공식 validator 증거를 검증하는 Sec Hub의 적용 방식입니다. 이 방식을 Cloudflare의 공식 Codex 통합이나 실제 실행 검증 완료로 주장하지 않습니다. quick profile의 정적 소스 검토이며 동적 exploit 확인을 주장하지 않습니다. 필수 workflow 단계, 공식 validator 두 개, 선택한 strategy의 실제 프로세스·역할 독립성 증거와 출력물을 확인한 경우에만 완료입니다. Anthropic은 pin `d3bea6b5793b5f3d59a75ebe69a58efa88383145`의 공식 Claude Code `/vuln-scan --single --no-score`를 실행합니다. 정적 candidate 검토이며 C/C++ Docker/gVisor/ASAN reference harness 실행과는 범위가 다릅니다. 두 workflow는 trusted runner의 새 소스 사본을 사용하고 원본과 사본의 입력 소스 보존, native 완료 증거 및 결과 schema를 검증합니다. 입력 수정이나 불완전 증거는 완료로 표시하지 않습니다.

`supervised-codex-workers`의 model-authored grouped exclusion catalog는 알려진 ID와 unit reference를 포함하며, 기존 full coverage 의미 검증과 hunter map에 그대로 확장한 뒤 검사합니다. source-only/known-fixture 정책은 계속 적용되고 의미 검증을 줄이지 않습니다. Recon 단계의 Codex `--output-schema` canary는 provider가 structured output schema를 받는지 확인할 뿐, source 검사나 전체 workflow 증거가 아닙니다. 각 role에는 별도 schema가 적용되며 recon canary 결과를 다른 role에 일반화하지 않습니다. malformed native JSON은 거부하며 문법을 자동 수정하지 않습니다. source claim을 만들어 내거나 자동 복구하지 않습니다. planner 제한은 최대 600초, 다른 역할은 최대 300초이며 전체 실행은 호출자의 남은 deadline과 최대 1800초에 묶입니다. `maxAgents` 최소 8은 역할 예약 조건이지 충분한 실행 예산의 보장은 아닙니다. 기본 최대 10은 이 작업에 명시적으로 높여야 할 수 있습니다. policy gate는 streamed text를 읽은 뒤 금지된 외부 SKILL 내용이나 정체 상태를 조기에 감지하지만, 파일시스템 접근을 예방하는 격리는 아닙니다. 이 실행은 vendor-certified가 아니며 source-only quick coverage입니다.

새 검사는 `preparationFrom`과 `preparationSha256`을 모두 생략합니다. 4개 recon과 planner가 native exit 0 및 schema-supported 출력으로 끝난 뒤 host ledger 정렬에서 실패한 이전 실행만 준비 단계 복구 대상으로 지원합니다. Cloudflare의 명시적 `strategy: "supervised-codex-workers"` 설정에 `preparationFrom: "/absolute/old-run/raw/cloudflare/execution-manifest.json"`과 그 원본 manifest의 SHA-256인 `preparationSha256: "<64자리 소문자 hex>"`를 함께 추가하고 아래처럼 새 출력 경로로 실행합니다. 이는 수동 import나 일반 resume가 아닙니다. 이전 실패 실행은 수정하지 않으며 같은 대상·pin·native 설정(예산 `maxAgents` 포함), 원본 artifact hash·실행 identity·소스 증거 및 현재 `preparePlan` 검증을 모두 다시 확인합니다. 재사용한 5개 역할도 새 예산에 포함하며 hunter·critic·verifier는 새로 실행합니다. receipt는 여러 실행 cohort의 출처를 보존하며 단일 신규 실행으로 표시하지 않습니다. 재귀 연결, 뒤 단계 재사용, native 실패나 누락·변조된 준비 증거는 거부합니다. 위의 source-only quick/known-fixture 및 text를 읽은 뒤 적용되는 policy gate 한계는 동일합니다.

```sh
node bin/sec-hub.mjs scan /path/to/repository --ai --tools cloudflare --config /absolute/preparation-reuse.config.json --timeout 1800 --out /absolute/new-preparation-run
```

JSON, HTML 및 SARIF의 tool execution 기록에는 mode, backend, source pin, 정적 검토 한계와 동적 검증 상태가 포함됩니다. 서로 다른 실행을 결합한 보고서는 aggregate 출처와 원본 실행 이력을 보존하며 단일 실행으로 표시하지 않습니다. 기존 다섯 CLI 결과와 두 새 workflow의 일곱 도구 검증 방법 및 실제 완료 여부는 새 검증 기록을 확인하세요.

보존된 다섯 CLI aggregate와 새 native 실행을 재검증해 결합하려면 아래 명령을 사용합니다. `--agents`는 반복할 수 있어 Cloudflare와 Anthropic을 서로 다른 실행 폴더에서 받을 수 있습니다. 모든 입력은 절대 경로여야 하며 `--out`은 새 외부 폴더여야 합니다. 각 agent 입력은 선택한 도구가 실제 완료된 원본 로컬 실행이어야 하고, 같은 도구의 중복 완료나 실패 실행은 허용하지 않습니다. helper는 대상 해시·출처·최종 redaction 이후 해시·native 실행 증거를 다시 검증합니다.

```sh
node scripts/verify-seven-tools.mjs --five /absolute/five-combined --agents /absolute/cloudflare-completed --agents /absolute/anthropic-completed --config /absolute/seven-tools.config.json --out /absolute/new-seven-verified
```

Anthropic 대기 중에는 실제 완료 증거가 있는 Cloudflare 실행만 다음처럼 결합할 수 있습니다. 이 명령은 사용 예시이며 현재 Cloudflare 완료를 뜻하지 않습니다.

```sh
node scripts/verify-seven-tools.mjs --five /absolute/five-combined --agents /absolute/cloudflare-completed --config /absolute/seven-tools.config.json --out /absolute/new-six-partial --allow-partial
```

`--allow-partial`은 누락된 agent를 완료로 바꾸지 않습니다. 위 여섯 도구의 증거가 모두 검증되면 결과는 `verifiedIntegrations: 6`, `status: "partial"`, `verificationPassed: false`, `pendingIntegrations: ["anthropic"]`이며 종료 코드는 **2**입니다. 일곱 도구 완료로 표시하지 않습니다. 이 옵션을 생략하면 두 agent의 완료 증거가 모두 필요하며, 일곱 도구가 전부 검증되어야 `verificationPassed: true`와 종료 코드 0을 반환합니다.


## 결과 해석

HTML 보고서는 각 도구의 selected/completed/skipped/failed/imported 상태, 실행 범위, 실패 사유, 미실행으로 인한 범위 제한을 함께 표시합니다. finding의 `candidate`, `reported`, `confirmed` 출처 상태를 구분합니다. 모든 검사가 완료되어 finding이 0건이어도 취약점이 없다는 증명은 아닙니다. SARIF에서 `unknown` 심각도는 `level: none`과 `properties.severity: unknown`으로 유지됩니다.

OSV의 취약점 DB 조회와 SkillSpector의 선택적 advisory 조회는 네트워크를 사용할 수 있으므로 완전한 오프라인 검사가 아닙니다. Codex Security 및 Open Code Review는 설정된 서비스에 코드를 업로드할 수 있습니다. PHP2Shell Checker는 지정 URL의 헤더/버전 휴리스틱 검사입니다. 도구 출력의 경고와 네트워크 동작은 해당 upstream 문서를 확인하세요. 비밀값 탐지는 일반적인 비밀 탐지기가 아닙니다.

## 외부 연결

- [Cloudflare Security Audit Skill](https://github.com/cloudflare/security-audit-skill) — 공식 Codex quick workflow 실행과 수동 bridge import를 지원합니다. 공식 `skills/security-audit/report-schema.json` 형식을 검증합니다.
- [Anthropic Defending Code Reference Harness](https://github.com/anthropics/defending-code-reference-harness) — 고정한 저장소의 라이선스는 Apache-2.0이며 README는 유지 관리되지 않는다고 설명합니다. 포함된 공식 Claude Code security skill의 정적 `/vuln-scan` mode를 실행합니다. 별도 C/C++ harness 실행은 포함하지 않으며 upstream 구현물을 Sec Hub에 번들하지 않습니다. 수동 import는 Sec Hub 계약 형식을 유지합니다.

양쪽 브리지의 가져오기용 스키마와 예시는 `node bin/sec-hub.mjs bridge <provider> --out <directory>`로 내보낼 수 있습니다. 이 저장소의 예시는 [Cloudflare](examples/cloudflare-bridge.json), [Anthropic](examples/anthropic-bridge.json)입니다.

## 개발

저장소의 자동화 테스트는 실행 인자, 파서, 정규화, 보고서와 가져오기 계약을 검사합니다. 모의/fixture 테스트 통과만으로 upstream 보안 검사기가 실제로 실행됐다고 볼 수 없습니다. 실제 upstream 실행 검증 여부는 실행 기록으로 별도 확인해야 합니다.

```sh
node --test
```

## 이번 빌드의 검증 결과

0.1.1은 자동 테스트 68개를 통과했고, Codex Security와 Open Code Review의 ChatGPT 인증을 포함한 실제 5개 CLI 검사에서 검증용 코드의 결과 13건을 수집했습니다. [통합 HTML 보고서](verification/authenticated-five-combined/report.html)와 [인증·실행 검증 기록](verification/AUTHENTICATED-VALIDATION.md)을 확인할 수 있습니다. 최초 실행과 OCR 예산 조정 재실행의 출처를 보존했으며, 동일 코드의 해시와 원본 결과를 검증해 결합했습니다. 다섯 도구의 실행 경로와 모델·제한 설정은 `verification/authenticated-tools.config.json`에 있습니다. 인증 정보는 패키지에 포함하지 않으며, 다른 기기에서는 도구 설치·로그인과 경로 변경이 필요합니다. 0.2.0은 이 이전 검증 이력을 보존하면서 Cloudflare/Anthropic의 공식 security skill 실제 실행 기능을 추가합니다. 새 일곱 도구 완료 주장은 별도 native 증거 검증 후에만 기록합니다.

## 현재 소스 개발자 워크벤치

현재 소스 commit `6381c306`의 저장 결과 화면은 한국어/영어를 지원하는 개발자 워크벤치로 바뀌었습니다. 현재 소스 미리보기는 [http://127.0.0.1:64076/](http://127.0.0.1:64076/)이며, 전체 검증과 증거 범위는 [개발자 워크벤치 보고서](verification/developer-workbench/REPORT.md)에 기록했습니다. 배포된 [0.2.3 패키지](releases/sec-hub-local-0.2.3.tgz)는 이 변경 전 파일이며 그대로 유지됩니다.

## 이전 웹 결과 화면 UX 검증의 미리보기 기록

이전 웹 결과 화면 UX 검증 당시, checkout의 결과 화면은 로컬에서 `node bin/sec-hub.mjs serve --runs /absolute/path/to/sec-hub-runs`를 실행해 loopback에서 확인했습니다. 당시 미리보기 주소는 [http://127.0.0.1:52557/](http://127.0.0.1:52557/)였으며, 이는 그 검증 당시 기록입니다. 이 작업 전 소스 시점은 `2caf`입니다. [웹 결과 화면 UX 검증 보고서](verification/web-results-ux/REPORT.md)에 당시 측정, 범위, 증거가 있습니다.
