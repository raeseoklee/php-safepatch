# php-safepatch 요구사항 명세

[English](SPEC.md) | 한국어 | [日本語](SPEC.ja.md)

## 1. 목적

php-safepatch는 서버에 있는 PHP 런타임을 찾아 advisory 기준으로 점검한다. 첫 advisory는 PHP2Shell(CVE-2026-109618, CVE-2026-109619)이다. 운영자가 승인하면 같은 마이너 브랜치 안에서 수정본을 설치한다. 수정본이 없는 런타임에는 advisory가 정한 임시 완화 설정을 적용한다.

가장 중요한 제약은 기존 애플리케이션이 계속 동작해야 한다는 점이다. 따라서 php-safepatch는 PHP의 메이저·마이너 버전을 절대 바꾸지 않는다(예: 8.2를 8.3으로 올리지 않는다).

## 2. 범위

| 환경 | 점검 | 패치 | 완화 |
|---|---|---|---|
| Debian / Ubuntu (apt, ondrej PPA 포함) | 지원 | 지원 (`phpX.Y-*` 패키지만) | 지원 |
| RHEL / Rocky / Alma (dnf·yum, Remi 포함) | 지원 | 지원 (브랜치가 바뀌면 중단) | 지원 |
| Windows (IIS FastCGI, Apache, 단독 설치) | 지원 | 지원 (windows.php.net의 같은 브랜치·빌드 zip) | 지원 |
| 실행 중인 Docker 컨테이너 | 지원 | 미지원 (이미지 재빌드 안내) | 미지원 |
| Dockerfile | 지원 | 지원 (`FROM php:` 태그의 패치 버전만 교체) | 해당 없음 |
| 소스 빌드 등 기타 경로 | 지원 | 미지원 (수동 조치 안내) | 지원 |

## 3. advisory 파일

취약점 하나에 해당하는 데이터는 모두 advisory 파일(`advisories/*.conf`)에 둔다. 새 PHP 취약점에 대응할 때는 파일만 추가하고 스크립트는 고치지 않는다.

| 키 | 뜻 |
|---|---|
| `id`, `cves` | 이름과 CVE 번호. 이름은 파일 이름과 표식에도 쓴다. |
| `fixed` | 지원 브랜치별 최소 해결 버전 |
| `eol_backport` | 벤더나 소스 백포트만 있는 지원 종료 브랜치 |
| `ioc_since` | 변경 파일 점검의 기준일 |
| `mitigate` | 임시 완화 규칙. 형식은 `INI_KEY=VALUE[@MIN_BRANCH]`이고 한 줄에 하나씩 쓴다. |
| `mitigate_optin` | 형식은 같다. 애플리케이션 동작을 바꿀 수 있으므로 `--include-optin`을 줄 때만 적용한다. |
| `ioc_log` | 로그 지표. 형식은 `LABEL|EXTENDED_REGEX`이다. |

## 4. 판정 기준

| 상태 | 조건 |
|---|---|
| `PATCHED` | 브랜치의 해결 버전 이상이거나, 배포판 패키지 변경 이력에 advisory의 CVE가 모두 있다. |
| `VULNERABLE` | 브랜치에 해결 버전이 있고, 런타임 버전이 그보다 낮다. |
| `VULNERABLE_EOL` | 브랜치가 `eol_backport`에 있다. 배포판이나 LTS 백포트가 있으면 설치하고, 없으면 완화 설정을 적용한다. |
| `VULNERABLE_NOFIX` | 모든 해결 브랜치보다 낮고 `eol_backport`에도 없다. 완화와 격리만 할 수 있다. |
| `RESTART_REQUIRED` | 디스크에서 교체된 바이너리를 실행 중인 프로세스가 아직 쓰고 있다. |
| `UNKNOWN` | 버전을 읽을 수 없다. |

## 5. 기능 요구사항

- **FR-1 탐색**: 알려진 경로, 실행 중인 프로세스, 패키지 DB, IIS·Apache 설정에서 PHP 런타임(CLI, FPM, CGI, mod_php)을 찾는다.
- **FR-2 판정**: 각 런타임을 4절 기준으로 판정한다.
- **FR-3 보고**: 사람이 읽는 표와 도구가 읽는 JSON 보고서를 만든다. 종료 코드는 모든 런타임이 안전하고 침해 지표가 없으면 0, 패치되지 않은 런타임이나 침해 지표가 있으면 1, 실행 오류가 나면 2이다.
- **FR-4 기본 동작은 무변경**: `scan`은 시스템을 바꾸지 않는다. 변경은 `apply`와 `rollback`에서만 하며, `--yes`가 없으면 호스트마다 확인을 받는다.
- **FR-5 브랜치 고정 패치**: 패키지를 설치하기 전에 트랜잭션을 시뮬레이션한다. 브랜치가 바뀌는 패키지가 있거나 apt 시뮬레이션에서 제거되는 패키지가 있으면 그 브랜치는 패치하지 않는다. Debian 계열에서는 기본 브랜치를 따라가는 메타패키지(`php`, `php-fpm`, `php-cli` 등)를 업그레이드하지 않는다. Windows에서는 브랜치, 스레드 안전성 모드, 컴파일러, 아키텍처가 모두 같은 zip만 설치한다.
- **FR-6 호환성 검증**: 변경 전후의 확장 모듈 목록(`php -m`)을 비교한다. 변경 후에 사라진 모듈이 있으면 실패로 처리한다. `--health-url`을 주면 변경 전후의 HTTP 상태도 비교한다.
- **FR-7 완화**: 패치 단계 뒤에도 취약한 런타임에는 advisory의 `mitigate` 규칙을 적용한다. `--include-optin`을 주면 `mitigate_optin` 규칙도 적용한다.
  - Linux: SAPI별 `conf.d` 파일, PHP-FPM 풀마다 `php_admin_value` 줄, mod_php용 Apache 설정의 `php_admin_value` 줄을 쓴다. 관리자 수준 값이라 `.user.ini`나 뒤쪽 풀 설정이 덮어쓰지 못한다.
  - Windows: 로드된 `php.ini`에 표식으로 감싼 블록을 넣는다. 블록은 첫 `[PATH=]`·`[HOST=]` 섹션 앞에 둔다. 그런 섹션 뒤의 값은 해당 경로나 호스트에만 적용되기 때문이다.
- **FR-8 백업과 롤백**: 파일을 바꾸기 전에 실행 ID별 디렉터리로 복사한다. 설정 검사(`php-fpm -t`, `apachectl -t`)나 FR-6 검증이 실패하면 파일을 자동으로 되돌린다. 패키지는 이전 버전을 기록해 두고 `rollback` 명령으로 다시 설치한다. Windows에서는 업데이트하는 PHP 디렉터리를 통째로 복사해 둔다.
- **FR-9 재시작**: 바뀐 런타임을 쓰는 서비스(PHP-FPM, Apache, IIS 애플리케이션 풀)를 재시작한다. `--no-restart`를 주면 재시작이 필요하다고 알리기만 한다. Windows에서는 사용 중인 파일이 잠기므로, 바이너리를 업데이트할 때는 항상 IIS나 Apache를 멈췄다가 다시 시작한다.
- **FR-10 침해 지표 점검**: 읽기 전용으로 advisory의 로그 패턴, PHP·웹 워커가 띄운 셸, `ioc_since` 이후 웹 디렉터리에서 바뀐 PHP 파일(흔한 웹셸 패턴 포함)을 확인한다.
- **FR-11 일괄 실행**: Ansible 플레이북으로 여러 호스트를 점검하고 적용한다. 적용은 한 번에 한 호스트씩(`serial: 1`) 진행하고, 첫 실패 호스트에서 멈춘다.

## 6. 비기능 요구사항

- **NFR-1 의존성**: Linux는 bash 4와 기본 유틸리티만 쓴다(jq 불필요). Windows는 PowerShell 5.1만 쓴다.
- **NFR-2 멱등성**: 같은 명령을 다시 실행해도 결과가 같다. 완화 블록을 표식으로 감싸므로 같은 블록이 두 번 들어가지 않는다.
- **NFR-3 무결성**: Windows에서는 zip의 SHA-256이 releases.json의 값과 같을 때만 설치한다.
- **NFR-4 추적성**: 실행마다 로그, 보고서, 백업을 `/var/lib/php-safepatch/<run-id>`(Windows는 `%ProgramData%\php-safepatch\<run-id>`)에 남긴다.

## 7. 범위 밖

- 마이너·메이저 버전 업그레이드
- Synology DSM 등 NAS·어플라이언스 펌웨어. DSM을 감지하면 아무것도 바꾸지 않고 멈춘다.
- PoC 실행 같은 능동적 공격 시험
- 침해 흔적 자동 삭제(증거 보존을 위해 보고만 한다)
- 인증정보 교체(보고서에서 권고만 한다)
