# php-safepatch 테스트

[English](TESTING.md) | 한국어 | [日本語](TESTING.ja.md)

php-safepatch는 운영 서버를 바꾸는 도구입니다. 그래서 스크립트를 고칠 때마다 아래 세 가지 테스트를 모두 통과해야 합니다. 테스트는 운영 서버가 아닌 시험용 장비에서 돌리세요.

| 테스트 | 명령 | 필요한 것 | 소요 시간 |
|---|---|---|---|
| 단위 | `tests/run.sh unit` | bash 4.4 (Linux, macOS, Git Bash) | 1분 (Git Bash에서는 약 5분) |
| 컨테이너 | `tests/run.sh containers` | Docker 또는 Podman, 인터넷 | 10~20분 |
| Windows | `tests\windows\run.ps1` | Windows, PowerShell 5.1, 인터넷 | 2~5분 |

## 단위 테스트

가짜 PHP 바이너리와 가짜 `dpkg-query`, `apt-get`을 씁니다. root 권한도, PHP도, 컨테이너도 필요 없습니다. 확인하는 항목은 다음과 같습니다.

- 버전별 판정(`VULNERABLE`, `PATCHED`, `VULNERABLE_EOL`, `VULNERABLE_NOFIX`)과 Dockerfile 태그별 판정
- 완화 파일: `conf.d` 파일, PHP-FPM 풀 섹션마다 끝에 붙는 블록, 8.5 전용 규칙, 선택 규칙
- 멱등성: 두 번째 실행에서는 아무것도 바뀌지 않음
- 롤백: 파일과 Dockerfile이 처음 상태로 돌아옴
- 처음부터 깨져 있던 PHP-FPM 설정: 해당 브랜치를 건드리지 않음
- 변경 때문에 설정 검사가 실패한 경우: 모든 파일이 실행 전 상태로 돌아옴
- 브랜치 고정: 같은 브랜치 안의 업그레이드는 진행하고, 시뮬레이션에서 다른 브랜치를 설치하거나 패키지를 제거하면 설치를 멈춤
- 버전 판정: advisory에 없는 브랜치(8.6.0)와 수정본 이후의 사전 릴리스(8.5.13-dev)는 `UNKNOWN`, 수정본의 사전 릴리스(8.5.12RC1)는 `VULNERABLE`이며, 배포판 접미사는 사전 릴리스로 보지 않음
- 완화를 읽지 않는 런타임은 `not_effective`로 판정하고 실행을 실패로 처리함
- PHP-FPM 풀: 표식 안에 잘못된 값이 있거나, 뒤쪽 풀 설정이 값을 되돌리면 `not_effective`로 판정함
- PHP-FPM include 순서: `include=z.conf`(0) 다음 `include=a.conf`(1)이면 `not_effective`, 순서가 반대면 `effective`이며, 중첩 include가 값을 되돌리면 `not_effective`로 판정함
- PHP-FPM 바이너리 하나를 systemd 유닛 두 개(`--fpm-config A`, `-y B -c php.ini`)가 쓰는 경우: 런타임 두 개로 나누고, 두 풀 모두 완화하고, 두 유닛 모두 재시작하며, 필드가 밀리지 않음
- auto 모드에서 패치된 브랜치는 PHP-FPM 풀 블록까지 포함해 남은 완화를 모두 지움
- 헬스 체크 URL이 200에서 404로 바뀌면 실행을 실패로 처리하고 파일을 되돌림
- advisory 파일은 빈 상태에서 읽고, 잘못된 파일이면 실행을 멈춤
- dnf 트랜잭션 검사: 모듈 스트림 변경, 패키지 제거, 다른 브랜치 패키지, 시뮬레이션 실패가 있으면 설치를 멈춤

## 컨테이너 테스트

실제 배포판 패키지를 설치한 컨테이너마다 root로 `tests/lib/cases.sh`를 실행합니다. 저장소는 `/src`에 읽기 전용으로 마운트합니다.

| 대상 | PHP | 확인하는 것 |
|---|---|---|
| `debian12` | `bookworm-security` 없이 릴리스 저장소에서 받은 8.2 | 보안 저장소를 통한 같은 브랜치 업그레이드, 변경 이력 확인, mod_php와 PHP-FPM |
| `ubuntu2204` | 릴리스 저장소에서만 받은 8.1 | 지원 종료 브랜치: 버전 번호는 그대로인 채 변경 이력으로 벤더 백포트를 알아봄 |
| `rocky9-appstream` | AppStream 모듈 `php:8.2` | 모듈 스트림 안에서 dnf 경로가 동작하는지, 벤더 수정본이 아직 없을 때 완화 설정이 들어가는지 |
| `rocky9-remi` | Remi 모듈 `php:remi-8.2` | 저장소에 8.3~8.5도 있지만 apply가 8.2에 머무는지 |

이미지마다 보안 저장소를 끈 채로 PHP를 설치한 뒤, 전체 저장소 목록을 되돌려 놓습니다. 그러면 php-safepatch는 패치하지 않은 실제 서버와 같은 상황을 보게 됩니다.

`tests/lib/cases.sh`는 다음 순서로 확인합니다.

1. `scan`이 `/etc`를 바꾸지 않습니다(실행 전후 체크섬 비교).
2. `apply --mitigate never`가 브랜치를 유지하고, 다른 브랜치의 패키지나 기본 브랜치 메타패키지를 설치하지 않으며, 확장 모듈도 모두 유지합니다.
3. `apply --no-patch --mitigate always`가 `conf.d` 파일과 PHP-FPM 풀 블록을 씁니다. `php -i`에 새 값이 보이고, `php-fpm -t`와 `apachectl -t`를 통과합니다.
4. 같은 명령을 한 번 더 실행해도 `/etc`가 바뀌지 않습니다.
5. 완화 실행을 `rollback`하면 파일이 사라지고, 패치 실행을 `rollback`하면 이전 패키지 버전이 다시 설치됩니다.
6. 처음부터 깨져 있던 PHP-FPM 설정이 있으면 `apply`는 종료 코드 2로 멈추고 아무것도 바꾸지 않습니다.

컨테이너마다 PHP-FPM을 별도 설정 파일(`-y /etc/php-custom/php-fpm.conf`)로 띄워 두고 다음을 확인합니다. php-safepatch가 패키지 기본값이 아니라 그 파일을 쓰는지, 패키지를 업그레이드한 뒤 마스터를 재시작하기 전까지 `RESTART_REQUIRED`로 판정하는지, 완화가 재시작 전에는 `pending_restart`이고 재시작 후에는 `effective`인지 봅니다.

같은 바이너리로 두 번째 마스터(`-y /etc/php-custom2/php-fpm.conf`)도 띄웁니다. 이 마스터가 별도 런타임으로 잡히는지, 첫 번째 마스터만 재시작했을 때 계속 `RESTART_REQUIRED`로 남는지, 풀에 완화가 들어가는지, 풀 설정이 값을 되돌리면 `not_effective`가 되는지 확인합니다.

일부 결과는 테스트하는 날의 저장소 상태에 따라 달라집니다.

- 패치 단계의 `SKIP`은 저장소에 더 새로운 패키지가 없다는 뜻입니다. 벤더가 아직 수정본을 내지 않았거나, 이미지가 이미 패치된 경우입니다.
- RHEL 패키지 롤백의 `WARN`은 이전 RPM이 저장소에서 사라졌다는 뜻입니다. RHEL 계열 저장소에서는 흔한 일입니다.

컨테이너에는 systemd가 없어서 `--no-restart`로 실행합니다. 서비스 재시작과 `--health-url`은 가상 머신에서 시험하세요(아래 참고).

### 실행

```bash
tests/run.sh containers
```

```bash
tests/run.sh containers debian12 rocky9-remi --runtime podman
```

로그는 `tests/out/<대상>.log`에 남습니다. 전에 빌드한 이미지로 다시 돌리려면 `--no-build`를 붙이세요.

### Windows에서 실행

컨테이너 테스트는 Windows의 Git Bash에서도 돌아갑니다. 다만 WSL 2와 컨테이너 런타임이 필요합니다.

1. 관리자 권한으로 WSL 2를 설치하고 Windows를 다시 시작합니다: `wsl --install -d Debian`
2. 컨테이너 런타임을 설치합니다. Docker Desktop은 일정 규모 이상의 회사에서는 유료 구독이 필요합니다. WSL 안에 Docker Engine이나 Podman을 설치하면 라이선스 비용이 들지 않습니다.
3. Git Bash나 WSL 셸에서 `tests/run.sh containers`를 실행합니다.

Podman을 쓴다면 짧은 이미지 이름(`debian:12`)을 Docker Hub에서 찾도록 설정해야 합니다. `/etc/containers/registries.conf.d/50-php-safepatch-tests.conf`에 다음 두 줄을 넣으세요.

```
unqualified-search-registries = ["docker.io"]
short-name-mode = "permissive"
```

2026-10-23 기준으로 Rocky AppStream과 Remi는 이미 PHP 8.2.35를 배포하고 있습니다. 그래서 Rocky 두 대상의 패치 단계는 `SKIP`으로 나오며, 이 대상들은 dnf 환경의 탐색, 완화, 롤백만 확인합니다.

## Windows 테스트

공식 PHP 구버전 빌드(기본값 8.3.35, NTS, x64)를 임시 디렉터리에 받아 다음을 확인합니다.

- `scan`이 버전과 빌드 종류를 알아봅니다.
- `apply`가 같은 브랜치·같은 빌드의 최신 릴리스를 SHA-256으로 검증해 설치하고, 확장 모듈을 모두 유지합니다.
- 완화 블록이 첫 `[PATH=]` 섹션 앞에 들어가서, `php -r`에서 새 값이 보입니다.
- `apply`를 한 번 더 실행해도 아무것도 바뀌지 않습니다.
- `rollback`이 이전 바이너리와 원래 `php.ini`를 되돌립니다.
- PHP 없이 하는 함수 검사: 판정·헬스 체크·인수 분리 함수를 구문 트리에서 꺼내 직접 시험합니다(8.6.0, RC·dev 빌드, 200 -> 404).
- 서비스 복구: 두 번째 Apache 서비스의 중지가 실패하면 첫 번째 서비스를 다시 시작하는지, 작업 중 예외가 나면 두 서비스를 모두 다시 시작하는지 확인합니다.
- 복구 뒤 보고서가 디스크의 버전을 다시 읽는지 확인합니다(8.3.36에서 8.3.35로 돌아가면 `VULNERABLE`).
- 버전을 읽을 수 없으면 이전의 `PATCHED`가 아니라 `UNKNOWN`으로 판정하는지 확인합니다.
- auto 모드에서 패치된 설치본의 남은 완화를 지우는지, advisory 파일을 빈 상태에서 읽고 검증하는지 확인합니다.

```powershell
powershell -ExecutionPolicy Bypass -File tests\windows\run.ps1
```

```powershell
powershell -ExecutionPolicy Bypass -File tests\windows\run.ps1 -OldVersion 8.2.34 -Build nts-Win32-vs16-x64
```

이 테스트는 IIS나 Apache를 건드리지 않습니다.

## 가상 머신에서 끝까지 시험

운영 서버에서 `apply`를 쓰기 전에, 쓰고 있는 OS 계열마다 가상 머신 한 대씩으로 시험하세요.

1. nginx와 PHP-FPM을 올린 Debian 12, Apache와 PHP-FPM(또는 mod_php)을 올린 Rocky 9을 준비합니다.
2. `sudo bash linux/php-safepatch.sh apply --health-url http://localhost/info.php`를 실행합니다.
3. 서비스가 재시작되는지, 헬스 체크 URL의 상태가 변경 전후로 같은지 확인합니다.
4. 변경 후 헬스 체크 URL이 HTTP 500을 내도록 만듭니다(예: 완화 설정이 켜지면 실패하는 파일). php-safepatch가 파일을 되돌리는지 확인합니다.
5. 이 가상 머신들을 대상으로 Ansible 플레이북을 실행합니다. 먼저 `scan`, 그다음 `-e safepatch_mode=apply` 순서입니다.

## 릴리스 전 확인

- `shellcheck -S warning linux/php-safepatch.sh tests/*.sh tests/*/*.sh` 결과가 깨끗해야 합니다.
- 세 테스트가 모두 통과해야 합니다. `SKIP`과 `WARN`이 있다면 이유를 모두 설명할 수 있어야 합니다.
- 세 언어의 문서가 같은 동작을 설명해야 합니다.
