# php-safepatch 요구사항 명세

[English](SPEC.md) | 한국어 | [日本語](SPEC.ja.md)

## 1. 목적

php-safepatch는 서버에 있는 PHP 런타임을 찾아 advisory 기준으로 점검한다. 첫 advisory는 PHP2Shell(CVE-2026-109618, CVE-2026-109619)이다. 운영자가 승인하면 같은 마이너 브랜치 안에서 수정본을 설치한다. 수정본이 없는 런타임에는 advisory가 정한 임시 완화 설정을 적용한다.

가장 중요한 제약은 기존 애플리케이션이 계속 동작해야 한다는 점이다. 따라서 php-safepatch는 PHP의 메이저·마이너 버전을 절대 바꾸지 않는다(예: 8.2를 8.3으로 올리지 않는다).

두 번째 제약은 보고서가 "안전"을 섣불리 말하지 않는 것이다. 런타임은 수정된 코드가 디스크에 있고, **동시에** 실행 중인 프로세스가 그 코드를 쓰고 있을 때만 안전하다. 완화 설정은 서비스가 실제로 그 값을 읽을 때만 적용된 것으로 본다.

## 2. 범위

| 환경 | 점검 | 패치 | 완화 |
|---|---|---|---|
| Debian / Ubuntu (apt, ondrej PPA 포함) | 지원 | 지원 (`phpX.Y-*` 패키지만) | 지원 |
| RHEL / Rocky / Alma (dnf·yum, Remi 포함) | 지원 | 지원 (트랜잭션이 브랜치를 바꾸면 중단) | 지원 |
| Windows (IIS FastCGI, Apache, 단독 설치) | 지원 | 지원 (windows.php.net의 같은 브랜치·빌드 zip) | 지원 |
| 실행 중인 Docker 컨테이너 | 지원 | 미지원 (이미지 재빌드 안내) | 미지원 |
| Dockerfile | 지원 | 지원 (`FROM php:` 태그의 패치 버전만 교체) | 해당 없음 |
| 소스 빌드 등 기타 경로 | 지원 | 미지원 (수동 조치 안내) | 지원 |

## 3. advisory 파일

취약점 하나에 해당하는 데이터는 모두 advisory 파일(`advisories/*.conf`)에 둔다. 새 PHP 취약점에 대응할 때는 파일만 추가하고 스크립트는 고치지 않는다.

| 키 | 필수 | 뜻 |
|---|---|---|
| `id` | 예 | 이름. `A-Z a-z 0-9 . _ -`만 쓴다. 파일 이름과 표식에도 쓴다. |
| `cves` | 예 | CVE 번호. 공백으로 구분한다. |
| `fixed` | 예 | 지원 브랜치별 최소 해결 버전(`X.Y.Z`) |
| `eol_backport` | 아니요 | 벤더나 소스 백포트만 있는 지원 종료 브랜치(`X.Y`) |
| `ioc_since` | 아니요 | 변경 파일 점검의 기준일(`YYYY-MM-DD`). 없으면 이 점검을 하지 않는다. |
| `mitigate` | 아니요 | 임시 완화 규칙. 형식은 `INI_KEY=VALUE[@MIN_BRANCH]`이고 한 줄에 하나씩 쓴다. |
| `mitigate_optin` | 아니요 | 형식은 같다. 애플리케이션 동작을 바꿀 수 있으므로 `--include-optin`을 줄 때만 적용한다. |
| `ioc_log` | 아니요 | 로그 지표. 형식은 `LABEL|EXTENDED_REGEX`이다. |

`--advisory`로 지정한 파일은 빈 상태에서 읽는다. 내장된 PHP2Shell 데이터는 하나도 이어받지 않는다. php-safepatch는 시스템을 읽기 전에 모든 키와 값을 검증한다. 모르는 키가 있거나, 필수 키가 없거나, 형식이 틀리면 아무것도 바꾸지 않고 종료 코드 2로 멈춘다.

## 4. 상태 모델

php-safepatch는 런타임마다 네 가지 사실을 따로 기록한다. 하나의 값으로 합치지 않는다.

| 필드 | 값 | 뜻 |
|---|---|---|
| `installed` | `PATCHED`, `VULNERABLE`, `VULNERABLE_EOL`, `VULNERABLE_NOFIX`, `UNKNOWN` | 디스크에 있는 바이너리의 판정(5절) |
| `running` | `yes`, `no`, `stale`, `unknown` | `stale`: 디스크에서 교체된 바이너리나 라이브러리를 아직 실행 중인 프로세스가 있다. `unknown`: 컨테이너 |
| `mitigation` | `none`, `effective`, `pending_restart`, `not_effective`, `unknown` | `effective`: 서비스가 지금 그 값을 읽는다. `pending_restart`: 파일은 들어갔지만 실행 중인 프로세스가 변경 전에 시작됐다. `not_effective`: 파일은 들어갔지만 런타임이 읽지 않는다. |
| `status` | `installed` 값 또는 `RESTART_REQUIRED` | `running`이 `stale`이면 `RESTART_REQUIRED`이다. 종료 코드는 이 필드를 따른다. |

침해 지표는 호스트 단위의 별도 목록으로 기록한다.

## 5. 판정 기준 (`installed`)

| 값 | 조건 |
|---|---|
| `PATCHED` | 정식 릴리스(사전 릴리스 접미사 없음)이면서 브랜치의 해결 버전 이상이거나, 배포판 패키지 변경 이력에 advisory의 CVE가 모두 있다. |
| `VULNERABLE` | 브랜치에 해결 버전이 있고 런타임이 그보다 낮다. 해결 버전의 사전 릴리스(예: `8.5.12RC1`)도 낮은 것으로 본다. |
| `VULNERABLE_EOL` | 브랜치가 `eol_backport`에 있다. 배포판이나 LTS 백포트가 있으면 설치하고, 없으면 완화 설정을 적용한다. |
| `VULNERABLE_NOFIX` | 모든 해결 브랜치보다 낮고 `eol_backport`에도 없다. 완화와 격리만 할 수 있다. |
| `UNKNOWN` | 버전을 읽을 수 없거나, advisory에 없는 브랜치이거나(예: `8.6.0`), 해결 버전 이후의 사전 릴리스 빌드다(예: `8.5.13-dev`). |

`-1ubuntu2.28` 같은 배포판 접미사는 사전 릴리스 접미사로 보지 않는다.

## 6. 기능 요구사항

- **FR-1 탐색**: 알려진 경로, 실행 중인 프로세스, 패키지 DB, IIS·Apache 설정에서 PHP 런타임(CLI, FPM, CGI, mod_php)을 찾는다.
- **FR-2 서비스 설정**: 런타임마다 그 서비스가 실제로 쓰는 설정을 찾는다.
  - Linux PHP-FPM: 실행 중인 마스터 프로세스 제목의 설정 파일을 먼저 쓴다. 그다음 systemd 유닛의 `-y`/`--fpm-config`, `-c`/`--php-ini`, `PHP_INI_SCAN_DIR`를 쓰고, 마지막으로 바이너리의 기본값을 쓴다.
  - Windows: CLI, IIS FastCGI 애플리케이션 각각(`arguments`와 `PHPRC`), Apache(`PHPIniDir`)가 읽는 `php.ini`를 찾는다.
  - 모든 점검, 설정 검사, 검증은 이 옵션 그대로 실행한다.
  - 런타임은 "바이너리 하나와 서비스 설정 하나"의 조합이다. PHP-FPM 바이너리 하나가 서로 다른 `-y` 파일로 여러 서비스를 돌리면(systemd 유닛이나 실행 중인 마스터), 서비스마다 별도 런타임으로 다룬다. 완화, 검증, 재시작, 판정을 각각 따로 하고, `running` 상태도 그 설정의 마스터를 기준으로 정한다.
- **FR-3 판정**: 런타임마다 4절의 네 필드를 기록한다.
- **FR-4 보고**: 사람이 읽는 표와 도구가 읽는 JSON 보고서를 만든다. 종료 코드는 모든 `status`가 `PATCHED`이고 침해 지표가 없으면 0, `PATCHED`가 아닌 런타임이나 침해 지표가 있으면 1, 실행 오류가 나면 2이다.
- **FR-5 기본 동작은 무변경**: `scan`은 시스템을 바꾸지 않는다. 변경은 `apply`와 `rollback`에서만 하며, `--yes`가 없으면 호스트마다 확인을 받는다.
- **FR-6 브랜치 고정 패치**: 패키지를 설치하기 전에 트랜잭션 전체를 시뮬레이션한다.
  - apt: `apt-get -s install --only-upgrade`로 시뮬레이션한다. 기본 브랜치를 따라가는 메타패키지(`php`, `php-fpm`, `php-cli` 등)는 업그레이드하지 않는다.
  - dnf·yum: `upgrade --assumeno`로 시뮬레이션하고, 의존성까지 포함한 트랜잭션 표를 읽는다.
  - 트랜잭션이 패키지를 제거·다운그레이드·대체하거나, 모듈 스트림을 바꾸거나, 다른 브랜치의 PHP 패키지를 건드리면 패치를 멈춘다.
  - 시뮬레이션이 실패하면 "업데이트 없음"이 아니라 오류로 처리한다.
  - Windows: 브랜치, 스레드 안전성 모드, 컴파일러, 아키텍처가 모두 같은 zip만 설치한다.
- **FR-7 사전 검사**: 아무것도 바꾸기 전에 서비스의 설정 그대로 PHP-FPM 설정 검사를 한다. 실패하면 그 브랜치는 건드리지 않는다.
- **FR-8 완화**: 패치 단계 뒤에도 디스크의 바이너리가 `PATCHED`가 아니면 `mitigate` 규칙을 적용한다. `--include-optin`을 주면 `mitigate_optin` 규칙도 적용한다.
  - Linux: SAPI별 `conf.d` 파일, 실제로 쓰는 PHP-FPM 설정의 풀마다 `php_admin_value` 줄, mod_php용 Apache 설정의 `php_admin_value` 줄을 쓴다.
  - Windows: FR-2에서 찾은 `php.ini`마다 표식으로 감싼 블록을 넣는다. 블록은 첫 `[PATH=]`·`[HOST=]` 섹션 앞에 둔다. 그런 섹션 뒤의 값은 해당 경로나 호스트에만 적용되기 때문이다.
  - 변경 후에는 각 서비스가 읽는 방식 그대로 값을 다시 읽는다. 값을 받지 못한 런타임이 있으면 오류(`not_effective`)로 처리한다.
  - PHP-FPM은 풀마다 키별 최종값을 계산한다. 마지막 `php_admin_value`/`php_admin_flag`가 우선이고, 없으면 마지막 `php_value`/`php_flag`, 그것도 없으면 `php.ini`와 `conf.d`의 값이다. 모든 풀의 최종값이 advisory 값과 같아야 한다. 블록의 표식만으로는 적용된 것으로 보지 않는다. "마지막"은 PHP-FPM이 읽는 순서를 따른다. `include`는 그 줄이 있는 위치에서 읽고(글롭은 C 로케일 바이트 순서), 중첩 include도 따라간다.
- **FR-9 완화 제거**: `--mitigate auto`에서 한 브랜치의 런타임이 모두 `PATCHED`가 되면, 그 advisory로 넣은 완화를 모두 지운다. `conf.d` 파일, PHP-FPM 풀 블록, Apache 파일, Windows `php.ini` 블록이 대상이다.
- **FR-10 백업과 롤백**: 파일을 바꾸기 전에 실행 ID별 디렉터리로 복사한다. 설정 검사, 확장 모듈 검사, 헬스 체크 중 하나라도 실패하면 파일을 자동으로 되돌린다. 패키지는 이전 버전을 기록해 두고 `rollback` 명령으로 다시 설치한다. Windows에서는 업데이트하는 PHP 디렉터리를 통째로 복사해 둔다.
- **FR-11 재시작과 재확인**: 바뀐 런타임을 쓰는 서비스(PHP-FPM, Apache, IIS 애플리케이션 풀)를 재시작한다. FR-2에서 찾은 systemd 유닛도 포함한다. 그다음 디스크의 버전, 프로세스, 완화 상태를 다시 읽고 다시 판정한다. 자동 복구가 일어났다면 보고서에는 복구된 버전이 나온다. 버전을 읽을 수 없으면 `UNKNOWN`으로 판정하고, 이전 값을 그대로 두지 않는다. `--no-restart`를 줬거나 재시작할 수 없으면 `status`는 `RESTART_REQUIRED`, 완화는 `pending_restart`로 남는다.
- **FR-12 Windows 서비스 복구**: Windows는 사용 중인 파일을 잠그므로, 바이너리를 업데이트할 때 IIS나 Apache를 멈춘다. 첫 서비스를 멈추는 순간부터 마지막 파일을 복사할 때까지를 하나의 `try`/`finally`로 묶는다. 서비스는 멈추는 즉시 목록에 기록한다. `finally`에서 일부만 복사된 파일을 되돌리고, 뒤쪽 서비스의 중지가 실패하거나 예외가 나도 이미 멈춘 서비스를 모두 다시 시작한다. 롤백할 때의 디렉터리 복원도 같은 방식을 쓴다.
- **FR-13 검증**: 변경 전후의 확장 모듈 목록(`php -m`)을 비교한다. 사라진 모듈이 있으면 실패로 처리한다. `--health-url`을 주면 URL마다 변경 후의 HTTP 상태 코드가 변경 전과 같아야 한다. 변경 전부터 실패하던 URL은 판단에 쓰지 않는다.
- **FR-14 침해 지표 점검**: 읽기 전용으로 advisory의 로그 패턴, PHP·웹 워커가 띄운 셸, `ioc_since` 이후 웹 디렉터리에서 바뀐 PHP 파일(흔한 웹셸 패턴 포함)을 확인한다.
- **FR-15 일괄 실행**: Ansible 플레이북으로 여러 호스트를 점검하고 적용한다. 적용은 한 번에 한 호스트씩(`serial: 1`) 진행한다. 오류(종료 코드 2)가 난 호스트에서 멈추고, 기본값으로는 아직 패치되지 않았거나 침해 지표가 나온 호스트(종료 코드 1, `safepatch_fail_on_unpatched: true`)에서도 멈춘다. 멈추기 전에 그 호스트의 보고서를 먼저 가져온다.

## 7. 비기능 요구사항

- **NFR-1 의존성**: Linux는 bash 4.4 이상과 기본 유틸리티(coreutils, grep, sed, awk, findutils)만 쓴다. jq와 diffutils는 필요 없다. Windows는 PowerShell 5.1만 쓴다.
- **NFR-2 멱등성**: 같은 명령을 다시 실행해도 결과가 같다. 완화 블록을 표식으로 감싸므로 같은 블록이 두 번 들어가지 않는다.
- **NFR-3 무결성**: Windows에서는 zip의 SHA-256이 releases.json의 값과 같을 때만 설치한다.
- **NFR-4 추적성**: 실행마다 로그, 보고서, 백업을 `/var/lib/php-safepatch/<run-id>`(Windows는 `%ProgramData%\php-safepatch\<run-id>`)에 남긴다.

## 8. 범위 밖

- 마이너·메이저 버전 업그레이드
- Synology DSM 등 NAS·어플라이언스 펌웨어. DSM을 감지하면 아무것도 바꾸지 않고 멈춘다.
- PoC 실행 같은 능동적 공격 시험
- 침해 흔적 자동 삭제(증거 보존을 위해 보고만 한다)
- 인증정보 교체(보고서에서 권고만 한다)
