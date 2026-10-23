# php-safepatch

[English](README.md) | 한국어 | [日本語](README.ja.md)

**PHP2Shell(CVE-2026-109618, CVE-2026-109619) 점검·패치 도구. Linux, Windows, Docker를 지원하며, PHP 브랜치를 바꾸지 않고 패치합니다.**

php-safepatch는 서버에 있는 PHP 런타임을 모두 찾아 어느 것이 취약한지 알려 주고, **PHP 마이너 버전을 바꾸지 않고** 고칩니다. 애플리케이션은 원래 쓰던 브랜치(예: 8.2는 8.2 그대로)에서 계속 돌아가므로, 업데이트 때문에 서비스가 깨지지 않습니다.

> PHP2Shell은 인증 없이 HTTP 요청 한 번으로 서버 명령을 실행할 수 있는 취약점입니다(CVSS 4.0 기준 9.2). 해결 버전은 **8.2.35, 8.3.36, 8.4.27, 8.5.12**입니다. PHP 8.1 이하는 공식 릴리스가 없습니다. 자세한 내용은 [PHP 보안 공지](https://www.php.net/)와 KISA 보호나라 공지를 확인하세요.

## 하는 일

1. **찾기**: CLI, PHP-FPM, CGI, mod_php는 물론 실행 중인 Docker 컨테이너 안의 PHP, Dockerfile의 `FROM php:` 줄, Windows의 IIS FastCGI와 Apache까지 찾습니다.
2. **판정**: 각 런타임을 advisory 기준으로 판정합니다. 배포판 벤더는 버전 번호를 그대로 둔 채 수정 사항만 백포트하는 경우가 많아서, 패키지 변경 이력(changelog)도 함께 확인합니다.
3. **같은 브랜치 안에서 패치**(승인한 뒤에만 진행):
   - Debian/Ubuntu: `phpX.Y-*` 패키지만 업그레이드합니다. 새 브랜치를 끌어올 수 있는 `php` 메타패키지는 건드리지 않습니다.
   - RHEL/Rocky/Alma: 설치 가능한 버전을 먼저 확인하고, 브랜치가 바뀌는 패키지가 하나라도 있으면 멈춥니다.
   - Windows: windows.php.net에서 같은 브랜치, 같은 빌드(TS/NTS, 컴파일러, x64/x86)를 받아 SHA-256을 검증한 뒤 설치합니다.
4. **완화**: 패치할 수 없는 런타임에는 임시 완화 설정을 적용합니다. PHP2Shell은 `session.upload_progress.enabled=0`을 설정하고, 8.5에서는 `fatal_error_backtraces=0`도 설정합니다. PHP-FPM과 mod_php에서는 관리자 수준으로 값을 고정해 애플리케이션이 덮어쓰지 못하게 합니다.
5. **검증**: 확장 모듈 목록이 그대로인지, 설정 검사를 통과하는지, 지정한 헬스 체크 URL이 계속 응답하는지 확인합니다. 하나라도 실패하면 바꾼 파일을 자동으로 되돌립니다.
6. **침해 지표 점검**(읽기 전용): 스크립트 실행 전에 일어난 메모리 오류, 워커 비정상 종료, PHP 워커가 띄운 셸, 첫 공격 보고 이후 바뀐 PHP 파일을 찾습니다.

## 빠른 시작

### Linux (Debian, Ubuntu, RHEL, Rocky, Alma)

```bash
curl -fsSLO https://raw.githubusercontent.com/raeseoklee/php-safepatch/main/linux/php-safepatch.sh
```

```bash
sudo bash php-safepatch.sh scan
```

```bash
sudo bash php-safepatch.sh apply --health-url https://your-site.example/
```

`scan`은 시스템을 바꾸지 않습니다. `apply`는 실행 계획을 먼저 보여 주고, 확인을 받은 뒤에 변경합니다.

### Windows (PowerShell 5.1, 관리자 권한으로 실행)

```powershell
powershell -ExecutionPolicy Bypass -File .\windows\php-safepatch.ps1 scan
powershell -ExecutionPolicy Bypass -File .\windows\php-safepatch.ps1 apply -HealthUrl https://your-site.example/
```

### 여러 서버에 적용 (Ansible)

```bash
cp ansible/inventory.example.ini ansible/inventory.ini
```

```bash
ansible-playbook -i ansible/inventory.ini ansible/site.yml
```

```bash
ansible-playbook -i ansible/inventory.ini ansible/site.yml -e safepatch_mode=apply
```

첫 번째 명령은 모든 호스트를 점검만 합니다. 두 번째 명령은 한 번에 한 호스트씩 적용하고, 실패한 호스트가 나오면 그 자리에서 멈춥니다. JSON 보고서는 `ansible/reports/`에 모입니다.

## 명령과 옵션

| Linux | Windows | 설명 |
|---|---|---|
| `scan` | `scan` | 보고만 합니다. 아무것도 바꾸지 않습니다. |
| `apply` | `apply` | 같은 브랜치 안에서 패치하고, 그래도 취약한 런타임에는 완화 설정을 적용합니다. |
| `rollback [--run-id ID]` | `rollback [-RunId ID]` | 지정한 실행에서 바꾼 파일, 디렉터리, 패키지를 되돌립니다. 지정하지 않으면 가장 최근의 `apply`를 되돌립니다. |
| `--yes` | `-Yes` | 확인 질문 없이 진행합니다. |
| `--json FILE` | `-Json FILE` | JSON 보고서를 저장합니다(`-`이면 표준 출력). |
| `--mitigate auto\|always\|never` | `-Mitigate ...` | `auto`는 패치 후에도 취약한 런타임에만, `always`는 패치된 런타임에도 적용합니다. |
| `--include-optin` | `-IncludeOptIn` | 선택 규칙도 적용합니다. PHP2Shell은 `memory_limit=-1`입니다(아래 설명 참고). |
| `--no-patch` | `-NoPatch` | 패키지나 바이너리는 설치하지 않고 완화 설정만 적용합니다. |
| `--no-restart` | `-NoRestart` | 서비스를 재시작하지 않습니다. |
| `--health-url URL` | `-HealthUrl URL` | 변경 전후로 이 URL을 확인합니다. 여러 번 지정할 수 있습니다. |
| `--php PATH` | `-Php PATH` | 자동 탐색으로 찾지 못한 PHP 바이너리나 디렉터리를 추가합니다. |
| `--web-root DIR` | `-WebRoot DIR` | 변경 파일 점검에 쓸 웹 루트를 추가합니다. |
| `--dockerfiles DIR` | | DIR 아래의 Dockerfile을 점검합니다. |
| `--fix-dockerfiles` | | `apply`와 함께 쓰면, 버전을 고정한 `FROM php:X.Y.Z` 태그를 해결 버전으로 바꿉니다. |
| `--no-docker`, `--no-ioc` | `-NoIoc` | 컨테이너 점검이나 침해 지표 점검을 건너뜁니다. |
| `--advisory FILE` | `-Advisory FILE` | 다른 advisory 파일을 씁니다. |
| `--state-dir DIR` | `-StateDir DIR` | 로그, 보고서, 백업을 저장할 위치입니다(기본값 `/var/lib/php-safepatch`, `%ProgramData%\php-safepatch`). |

종료 코드: `0`은 모든 런타임이 패치되었고 침해 지표도 없음, `1`은 패치되지 않은 런타임이나 침해 지표가 있음, `2`는 실행 오류입니다.

## 상태 값

| 상태 | 뜻 | 조치 |
|---|---|---|
| `PATCHED` | 해결 버전이거나, 벤더 패키지 변경 이력에 CVE가 있음 | 없음 |
| `VULNERABLE` | 같은 브랜치에 해결 버전이 있음 | `apply` 실행 |
| `VULNERABLE_EOL` | 7.4~8.1: 공식 릴리스 없음 | 배포판이나 LTS 업체의 백포트가 있으면 설치합니다. 없으면 완화 설정을 적용하고, 애플리케이션 테스트를 거쳐 업그레이드를 계획합니다. |
| `VULNERABLE_NOFIX` | 7.3 이하: 수정본 없음 | 완화 설정을 적용하고, 인터넷에서 격리한 뒤 업그레이드를 계획합니다. |
| `RESTART_REQUIRED` | 수정본은 디스크에 있지만, 프로세스가 아직 교체 전 바이너리를 쓰고 있음 | 서비스를 재시작합니다. |
| `UNKNOWN` | 버전을 읽을 수 없거나, advisory에 없는 브랜치(예: 8.6)이거나, 사전 릴리스 빌드임 | PHP와 벤더 보안 공지를 직접 확인합니다. |

"패치됨"과 "안전함"을 섞지 않도록, 보고서는 런타임마다 두 가지 정보를 더 보여 줍니다.

- `running`: `yes`, `no`, `stale`(프로세스가 교체 전 코드를 실행 중)
- `mitigation`: `none`, `effective`(서비스가 값을 읽고 있음), `pending_restart`(파일은 들어갔지만 프로세스가 변경 전에 시작됨), `not_effective`(파일은 들어갔지만 서비스가 읽지 않음, 오류로 처리)

php-safepatch는 서비스마다 실제로 쓰는 설정을 읽습니다. 실행 중인 PHP-FPM 마스터의 `-y` 파일, systemd 유닛의 `-c`와 `PHP_INI_SCAN_DIR`가 여기에 해당합니다. Windows에서는 IIS FastCGI 애플리케이션마다 `arguments`와 `PHPRC`, 그리고 Apache의 `PHPIniDir`를 읽습니다. 헬스 체크 URL은 변경 후에도 변경 전과 같은 상태 코드를 돌려줘야 통과합니다. Ansible의 `apply`는 아직 패치되지 않은 호스트를 만나면 멈춥니다. 계속 진행하려면 `safepatch_fail_on_unpatched=false`를 지정하세요.

## 완화 설정에 관해

PHP 보안팀은 업데이트만이 PHP2Shell을 완전히 막는다고 밝혔습니다. 완화 설정은 노출 범위를 줄일 뿐입니다.

- `session.upload_progress.enabled=0`은 CVE-2026-109619를 막습니다. 세션 업로드 진행률 기능을 쓰는 업로드 진행 표시줄이 동작하지 않게 되지만, 이 기능을 쓰는 애플리케이션은 많지 않습니다.
- `memory_limit=-1`(선택 규칙)은 CVE-2026-109618의 알려진 공격 경로를 막습니다. 대신 요청마다 걸리던 메모리 상한이 사라집니다. 컨테이너, cgroup, PHP-FPM의 메모리 제한과 함께 쓰세요. `--include-optin`을 주지 않으면 적용하지 않습니다.
- `RLIMIT_AS`나 `RLIMIT_DATA`로 완화하려 하지 마세요. 공격에 필요한 메모리 할당 실패를 오히려 일으킬 수 있습니다.
- 리버스 프록시나 웹 방화벽에서 요청 크기도 제한하세요. `Content-Length`가 없는 요청도 포함해야 합니다. 방법은 다음 절을 참고하세요.

## 리버스 프록시·웹 방화벽에서 막기

당장 패치할 수 없다면, 아래 규칙으로 알려진 공격 요청이 PHP에 닿기 전에 막을 수 있습니다. 업데이트를 대신하지는 못합니다. 각 규칙은 ModSecurity 2.9(OWASP CRS 포함), nginx(stable), Apache 2.4에서 공격 형태의 요청과 정상 요청으로 시험했습니다.

| 규칙 | ModSecurity | nginx | Apache |
|---|---|---|---|
| `PHP_SESSION_UPLOAD_PROGRESS` 필드 차단 (CVE-2026-109619) | 모든 경로 | 업로드가 없는 경로만 | 업로드가 없는 경로만 |
| 지나치게 긴 파라미터 이름 차단 (CVE-2026-109618) | 가능 | 불가 | 불가 |
| 본문 크기 제한 (chunked 요청 포함) | 가능 (CRS 기본값) | 가능 | 가능 |

**ModSecurity (v2·v3, CRS 사용 여부와 무관).** CRS 규칙보다 먼저 읽히는 파일(예: `REQUEST-899-PHP2SHELL.conf`)에 넣으세요. `session.upload_progress.name`을 기본값에서 바꿨다면 첫 번째 규칙에 그 값을 쓰세요.

```apache
# CVE-2026-109619: block the session upload progress field in multipart requests.
SecRule ARGS_NAMES "@streq PHP_SESSION_UPLOAD_PROGRESS" \
    "id:1026101,phase:2,deny,status:403,log,t:none,msg:'PHP2Shell: session upload progress field (CVE-2026-109619)'"
# CVE-2026-109618: block very long parameter names (the known attack uses one of about 3.5 MB).
SecRule ARGS_NAMES "@gt 1024" \
    "id:1026102,phase:2,deny,status:403,log,t:none,t:length,msg:'PHP2Shell: parameter name longer than 1024 bytes (CVE-2026-109618)'"
```

`SecRequestBodyNoFilesLimit`는 작게(기본값 128KB) 두고, `SecRequestBodyLimitAction Reject`를 유지하세요.

**nginx.** nginx는 폼 필드 이름을 읽지 못합니다. 그래서 업로드를 받지 않는 location에서 multipart 요청 자체를 막습니다.

```nginx
client_max_body_size 8m;          # also applies to chunked requests

location / {                      # locations without file uploads
    if ($content_type ~* "^multipart/form-data") { return 403; }
    # ... your fastcgi_pass or proxy_pass ...
}
```

**ModSecurity 없는 Apache.** `%{CONTENT_TYPE}`이 아니라 `%{HTTP:Content-Type}`을 쓰세요. Apache 표현식에서 `%{CONTENT_TYPE}`은 응답의 Content-Type이라서, 이것으로 만든 규칙은 아무것도 막지 못합니다.

```apache
LimitRequestBody 8388608          # also applies to chunked requests

<LocationMatch "^/(?!upload)">    # paths without file uploads
    <If "%{HTTP:Content-Type} =~ m#^multipart/form-data#i">
        Require all denied
    </If>
</LocationMatch>
```

참고:

- 웹 방화벽이나 프록시가 복호화된 트래픽을 볼 수 있어야 합니다. TLS를 종료하는 지점에 규칙을 두세요.
- 크기 제한은 실제 업로드 크기를 보고 정하세요. 너무 작으면 파일 업로드가 깨집니다.
- nginx와 Apache는 업로드 경로에서 이 필드를 막지 못합니다. 업로드 경로가 있는 서버부터 패치하거나, 그 서버에는 ModSecurity를 쓰세요.
- 운영에 적용하기 전에 스테이징 서버에서 먼저 시험하세요.

## 환경별 참고 사항

- **Synology DSM 등 NAS·어플라이언스 펌웨어**: 지원하지 않습니다. DSM에서 실행하면 아무것도 바꾸지 않고 멈춥니다. 제조사가 제공하는 업데이트를 쓰세요(Synology는 패키지 센터에서 PHP 패키지를 업데이트).
- **Docker**: 실행 중인 컨테이너는 바꾸지 않습니다. 해결 버전 태그(예: `php:8.2.35-fpm`)로 이미지를 다시 빌드해 배포하세요. `REBUILD`는 태그가 브랜치를 따라가므로(`php:8.2-fpm`) `--pull`로 다시 빌드하면 된다는 뜻입니다. `FLOATING_MAJOR`는 태그(`php:8`, `php:latest`)가 다시 빌드할 때 브랜치를 바꿀 수 있다는 뜻이므로, 태그를 고정하세요.
- **소스 빌드, Plesk, cPanel, LiteSpeed**: 찾아서 완화 설정까지는 적용합니다. 업데이트는 각 벤더의 도구로 하세요.
- **Debian/Ubuntu의 PHP 7.4~8.1**: ondrej PPA나 Debian LTS/ELS에 백포트가 있을 수 있습니다. 저장소가 같은 브랜치의 새 패키지를 제공하면 설치하고, 변경 이력으로 수정 여부를 확인합니다.

## 새 advisory 추가

`advisories/php2shell.conf`를 복사해 값을 바꾸고 `--advisory`/`-Advisory`로 지정하세요. 해결 버전, 완화 규칙, 로그 지표를 모두 이 파일에서 정의하므로 스크립트는 고치지 않아도 됩니다. 형식은 [SPEC.ko.md](SPEC.ko.md#3-advisory-파일)를 참고하세요.

## 침해 지표가 나왔을 때

1. 서버를 네트워크에서 격리하세요. 전원을 끄지는 마세요. 재시작하면 메모리에 남은 증거가 사라집니다.
2. 로그, 프로세스 목록, 네트워크 연결 정보를 보존하세요.
3. KISA 보호나라 등 관할 기관에 신고하세요.
4. PHP를 업데이트하고 웹셸을 지운 다음, DB 비밀번호, API 키, 관리자 비밀번호를 교체하세요.

인터넷에 도는 PoC로 서버를 시험하지 마세요. 악성코드가 들어 있는 경우가 많습니다.

## 테스트

테스트는 세 가지입니다. 가짜 바이너리로 돌리는 단위 테스트(`tests/run.sh unit`), 실제 배포판을 컨테이너로 띄우는 테스트(`tests/run.sh containers`), 공식 PHP 빌드로 돌리는 Windows 테스트(`tests\windows\run.ps1`)입니다. 자세한 내용은 [TESTING.ko.md](TESTING.ko.md)를 참고하세요. 운영 서버에서 `apply`를 쓰기 전에 스테이징 서버에서 먼저 시험하세요.

## 라이선스

[MIT](LICENSE)
