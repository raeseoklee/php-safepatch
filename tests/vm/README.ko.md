# 실제 systemd·RPM 업그레이드 테스트

[English](README.md) | 한국어 | [日本語](README.ja.md)

`run-rocky9.sh`는 일회용 Rocky Linux 9 KVM 가상 머신을 만듭니다. 호스트에는 php-safepatch를 실행하지 않습니다. 게스트는 공식 Rocky 9.5 보관 저장소(vault)에서 GPG 서명을 확인한 PHP 8.2.25 RPM을 설치한 뒤, 현재 저장소로 실제 업그레이드를 합니다.

## 필요한 것

- 읽기와 쓰기가 모두 가능한 `/dev/kvm`이 있는 Linux 호스트, 여유 메모리 4GiB, 여유 디스크 약 4GiB(이미지 캐시용 1.5GiB 별도), 인터넷 연결
- 명령: `qemu-system-x86_64`, `qemu-img`, `cloud-localds`, `ssh`, `ssh-keygen`, `curl`, `tar`, `sha256sum`. Debian/Ubuntu에서는 `qemu-system-x86`, `qemu-utils`, `cloud-image-utils`, `openssh-client`를 설치하면 됩니다.
- 로컬 포트 `127.0.0.1:22229`가 비어 있어야 합니다. 이 포트를 다른 프로그램이 쓰고 있으면(예: `VM_KEEP_RUNNING=1`로 남겨 둔 이전 게스트) 부팅 전에 멈춥니다. 한 번에 하나만 실행하세요.

## 실행

```bash
sudo bash tests/vm/run-rocky9.sh
```

WSL 2와 KVM을 쓸 수 있다면 PowerShell에서 실행합니다(저장소 경로는 환경에 맞게 바꾸세요).

```powershell
wsl -d Debian -u root -- bash /mnt/c/Workspace/phpdoctor/tests/vm/run-rocky9.sh
```

## 확인하는 것

- 실제 dnf 트랜잭션(`php-safepatch apply`, 가짜 도구 없음): 브랜치와 확장 모듈이 그대로 유지되는지
- 설정이 서로 다른 PHP-FPM systemd 서비스 두 개(기본 서비스와 `-y` 서비스): 둘 다 찾아내는지, 둘 다 재시작되는지(MainPID 변경), 업그레이드 후 둘 다 `PATCHED / running=yes`인지
- 완화 뒤 두 웹 SAPI가 HTTP로 실제로 돌려주는 값
- auto 모드의 완화 제거: 보고서의 모든 런타임이 `mitigation=none`인지, `conf.d` 파일과 두 풀 블록이 사라졌는지, 두 SAPI가 원래 값을 다시 돌려주는지
- 완화 뒤 HTTP 500이 나는 경우: 종료 코드 2로 끝나는지, 파일이 복원되는지(보고서와 파일 모두 확인), 두 서비스가 계속 active인지, 두 SAPI가 원래 값을 다시 돌려주는지

SELinux는 enforcing 상태를 유지합니다. 구버전 패키지는 보관 저장소에서 가져오므로, 운영 저장소에 오래된 RPM이 남아 있을 필요가 없습니다. 이 테스트는 AppStream 경로만 다룹니다. Remi, yum, Debian 서비스, mod_php, 패키지 다운그레이드 경로는 이 결과로 증명되지 않습니다.

## 증거

증거는 `tests/out/vm-rocky9-<UTC 타임스탬프>/`에 남습니다(git 추적 대상 아님).

- `host-sha256.txt`(실행 스크립트, 게스트 테스트, 제품 스크립트, advisory)와 `source-sha256.txt`(게스트에서 계산)
- `image.txt`, `image-checksum.txt`, `CHECKSUM`: 사용한 이미지와 공식 SHA-256
- `serial.log`, `test.log`, `guest.log`, `selinux.txt`
- `dnf-transaction.txt`, `packages.before.txt`, `packages.after.txt`, `modules.*.txt`
- `patch|mitigation|cleanup|rollback.json`과 `.log`: 단계별 php-safepatch 보고서와 출력
- `health-*.json`: 단계마다 두 SAPI가 돌려준 HTTP 응답
- `services.after-patch.txt`, `service-journal.txt`

## 이미지 캐시와 정리

- 기본 이미지는 `/var/tmp/php-safepatch-vm-cache/Rocky-9.qcow2`에 캐시합니다(`VM_CACHE`로 위치를 바꿀 수 있습니다). 실행할 때마다 공식 HTTPS 체크섬 목록을 읽습니다. Rocky가 새 `latest` 이미지를 내면 캐시가 체크섬과 맞지 않게 되는데, 이때는 한 번 다시 내려받습니다. 다시 받아도 맞지 않으면 실행을 멈춥니다. 실행에 쓴 체크섬은 `image.txt`에 남깁니다.
- 실행이 끝나면 게스트를 멈추고, 그 게스트의 오버레이 디스크와 개인 SSH 키(`/var/tmp/php-safepatch-kvm.*`)를 지웁니다.
- `VM_KEEP_RUNNING=1`을 주면 디버깅을 위해 게스트를 켜 둡니다. `VM_KEEP_FILES=1`을 주면 게스트는 멈추되 파일은 남깁니다. 남겨 둔 디렉터리에는 게스트의 root SSH 키가 있으니 비공개로 다루세요.
- 남겨 둔 파일과 이미지 캐시를 지우려면 다음 명령을 쓰세요.

```bash
sudo rm -rf /var/tmp/php-safepatch-kvm.* /var/tmp/php-safepatch-vm-cache
```

`VM_OUTPUT`으로 증거 디렉터리를 바꿀 수 있습니다.
