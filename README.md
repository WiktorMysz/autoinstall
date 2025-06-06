**Podsumowanie procesu instalacji:**

Proces instalacji obejmuje dwa kluczowe etapy:   
- Pierwszy to **autonomiczna instalacja minimalnego systemu Ubuntu** za pomocą konfiguracji `cloud-init`. Ustawia ona sieć `DHCP`, tworzy użytkownika z dostępem `SSH` (w tym klucz publiczny), konfiguruje partycjonowanie dysku (`EFI, Swap`) oraz uruchamia skrypty rejestracji maszyny w `Ansible`.  
- Drugi etap to **zdalna konfiguracja serwera przez Ansible**, która obejmuje aktualizację BIOS-u narzędziem `Supermicro SAA`, tworzenie macierzy `RAID 1` na dwóch dyskach, instalację zależności, aktualizację źródeł pakietów oraz przygotowanie systemu pod kątem pracy produkcyjnej.  
  
Automatyzacja pozwala na **jednoczesną instalację i konfigurację dziesiątek serwerów** w identyczny sposób, eliminując błędy ludzkie i oszczędzając czas, tworzy fundament dla inteligentnego monitoringu i zarządzania infrastrukturą IT. Każdy krok jest powtarzalny, dokumentowany i łatwy do modyfikacji.  

---

**Wynik końcowy:**  
Gotowy serwer Ubuntu 24.04 z:
- Zaktualizowanym BIOS-em,
- Macierzą RAID 1 zabezpieczającą dane,
- Konfiguracją sieciową i użytkowników,
- Gotowym do pracy środowiskiem (np. SSH, narzędzia diagnostyczne).  

---

**Przyszłe możliwości rozszerzeń:**  
Po zakończeniu instalacji system może automatycznie:  
- **Pobierać dane sprzętowe** (numery seryjne, adresy MAC, licencje systemu),
- **Zapisywać je w bazie danych** lub wysyłać na e-mail,
- **Generować i drukować etykiety** z informacjami o serwerze.  
To upraszcza zarządzanie infrastrukturą i tworzy spójne archiwum sprzętu.

---

**Uwagi techniczne i plany rozwoju:**  
- Kod został stworzony do testów i wymaga doprecyzowania parametrów (np. ścieżki plików, wersji BIOS-u, listy pakietów).  
- Niektóre pakiety (np. `ipmitool`, `saa`, `python3`) są instalowane tylko w celu konfiguracji i mogą zostać usunięte po instalacji za pomocą skryptu czyszczenia.  
- W przyszłości proponowane jest **zrezygnowanie z haseł** na rzecz logowania wyłącznie przez klucze SSH, co zwiększy bezpieczeństwo i uprości zarządzanie dostępem.

---
## **Opis wyjaśniający przeznaczenie pliku**
## cloud-init-user-data:

```yaml
#cloud-config
# Configuration for Ubuntu Autoinstall using cloud-init
# This file automates the installation and initial setup of a minimal Ubuntu system

autoinstall:
  version: 1
  reboot: true                        # Reboot the system after installation completes
  minimal_install: true               # Perform a minimal installation (no GUI or extra packages)

  network:
    version: 2                        # Use Netplan format version 2 for networking
    ethernets:
      en:                             # Configure Ethernet interfaces matching 'en*'
        match:
          name: en*                   # Match any interface starting with 'en' (Ethernet)
        dhcp4: true                   # Use DHCPv4 to obtain IPv4 address
        nameservers:
          addresses:
            - 8.8.8.8                 # Primary DNS server (Google)
            - 8.8.4.4                 # Secondary DNS server (Google)

  user-data:
    # Commands to run once, during first boot
    runcmd:
      - |
        echo "--- Waiting for network ---"
        timeout=60                    # Set timeout for waiting on network
        while ! ping -c 1 8.8.8.8; do # Wait until internet becomes available
          sleep 1
          timeout=$((timeout - 1))
          if [ $timeout -le 0 ]; then
            echo "Error: Network not available after 60 seconds"
            exit 1
          fi
        done
      - |
        IP=$(hostname -I | awk '{print $1}')  # Get primary IP address
        for i in {1..5}; do                    # Try up to 5 times
          curl -s -X POST http://192.168.50.1/hook/register -d "{\"ip\": \"$IP\"}" && break || sleep 20
        done
        if [ $? -ne 0 ]; then                  # If all attempts failed
          echo "ERROR: Failed to register client" >&2
          exit 1
        fi
      - |
        for i in {1..5}; do                    # Try up to 5 times
          curl -s -X GET http://192.168.50.1/hook/run_playbook && break || sleep 2
        done
        if [ $? -ne 0 ]; then                  # If request fails
          echo "ERROR: Failed to trigger Ansible playbook" >&2
          exit 1
        fi

    hostname: soundcorehero           # Set the hostname of the machine
    locale: en_US.UTF-8               # System locale
    timezone: Europe/Warsaw           # Timezone setting
    users:
      - name: player                  # Create a new user named 'player'
        gecos: player                 # Full name or description
        shell: /bin/bash              # Default shell
        groups: [adm, sudo, dip, plugdev, lxd]  # Additional groups for the user
        sudo: ALL=(ALL) NOPASSWD:ALL  # Allow passwordless sudo
        lock_passwd: false            # Password is not locked
        hashed_passwd: $6$rounds=500000$stpDd90q5q0vox.$B0cLlMNorDOgnbJHN5kuy9jDJHre4NDH6LiDssbxW7HwrKMMvEoifzwlBWLlRE.3fUoN.l8etgCQRAy8EyGaa1
                                      # SHA-512 hash of password 
        ssh_authorized_keys:
          - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDQeU4xpQ27aqRsx07rRWRO15u5zzlldldreZv9Su+D7 PXE-server
                                      # Allow SSH login without password

  ssh:
    install-server: true             # Install OpenSSH server

  keyboard:
    layout: us                       # Keyboard layout (US English)

  packages:
    - python3                        # Install Python 3
    - python3-pip                    # Install Python package manager
    - curl                           # Install cURL utility

  storage:
    config:
      - type: disk
        id: disk0
        match: { path: /dev/sda }    # Target the main disk at /dev/sda
        wipe: superblock-recursive   # Clear existing data before partitioning
        ptable: gpt                  # Use GPT partition table

      - type: partition
        id: part_esp
        device: disk0
        size: 1024M                  # First partition: 1GB for EFI system partition
        number: 1
        grub_device: true            # Mark as GRUB bootable

      - type: format
        id: format_esp
        volume: part_esp
        fstype: fat32                # Format ESP as FAT32

      - type: mount
        id: mount_esp
        device: format_esp
        path: /boot/efi              # Mount ESP at /boot/efi

      - type: partition
        id: part_swap
        device: disk0
        size: 2048M                  # Second partition: 2GB for Swap
        number: 2

      - type: format
        id: format_swap
        volume: part_swap
        fstype: swap                 # Format as Swap

      - type: partition
        id: part_root
        device: disk0
        size: -1                     # Third partition: use remaining space
        number: 3

      - type: format
        id: format_root
        volume: part_root
        fstype: ext4                 # Format root as ext4

      - type: mount
        id: mount_root
        device: format_root
        path: /                      # Mount root at /
```

---

Ten plik to konfiguracja typu `#cloud-config` przeznaczona dla systemu **Ubuntu Autoinstall**, która automatyzuje instalację systemu z użyciem narzędzi takich jak `cloud-init`.  
Plik ten automatyzuje całkowicie instalację i konfigurację systemu Ubuntu w środowisku `PXE`, tworząc gotową maszynę z zalogowaniem przez `SSH`, konfiguracją sieciową, partycjonowaniem dysku oraz integracją z `Ansible`.

### Ogólne ustawienia:
- Instalacja minimalna systemu Ubuntu.
- Po zakończeniu instalacji system zostanie **automatycznie uruchomiony ponownie**.
- Używana jest sieć z konfiguracją **DHCP** na interfejsie Ethernet (`en*`) z serwerami DNS od Google (`8.8.8.8`, `8.8.4.4`).

### Konfiguracja użytkowników:
- Tworzony jest użytkownik o nazwie `player` z uprawnieniami sudo (bez hasła).
- Hasło użytkownika zostało zahashowane.
- Dodano klucz SSH, który pozwala na logowanie bez hasła przez SSH.

### Podstawowe ustawienia systemu:
- Nazwa hosta: `soundcorehero`
- Lokalizacja: `en_US.UTF-8`
- Strefa czasowa: `Europe/Warsaw`
- Ustawienie klawiatury na amerykańską (`us`).

### Serwer SSH:
- Zainstalowany zostanie serwer OpenSSH, umożliwiając zdalne zarządzanie maszyną przez SSH.

### Pakiety:
- Do systemu tymczasowo zainstalowane pakiety wymagane do działania playbooków Ansible (mogą zostać usunięte po zakończeniu konfiguracji):
  - `python3`
  - `python3-pip`
  - `curl`

### Partycjonowanie dysku:
Konfiguracja dotyczy dysku `/dev/sda` z tabelą partycji GPT:
1. **EFI System Partition (ESP)** – 1 GB, sformatowana jako FAT32, zamontowana pod `/boot/efi`.
2. **Swap** – 2 GB, używany jako pamięć wirtualna systemu.
3. **Root (/)** – reszta wolnego miejsca na dysku, sformatowana jako ext4, zamontowana jako główny katalog systemu.

### Skrypty wykonywane po instalacji:
1. **Oczekiwanie na dostępność sieci** – sprawdza czy system ma dostęp do internetu poprzez pingowanie `8.8.8.8` maksymalnie przez 60 sekund.
2. **Rejestracja klienta** – wysyła żądanie POST z adresem IP maszyny do adresu `http://192.168.50.1/hook/register`. Próbuje do 5 razy, jeśli nie uda się – kończy się błędem.
3. **Uruchomienie playbooka Ansible** – wysyła żądanie GET do `http://192.168.50.1/hook/run_playbook`, również z próbami powtórzeń. Jeśli się nie uda, kończy się błędem.

---
## **Opis wyjaśniający przeznaczenie pliku**
## playbook.yml:

```yaml
---
- name: Remote BIOS and RAID configuration (Ubuntu 24.04)
  hosts: SCH
  gather_facts: yes
  become: yes

  vars:
    # Local path to SAA tool on the controller machine
    local_saa_linux_path: "/opt/iventoy/user/files/saa"
    # Target remote path for SAA tool
    remote_saa_linux_path: "/opt/supermicro/saa"
    # Path to BIOS firmware file locally
    firmware_file_local: "/opt/iventoy/user/files/bios/BIOS_A2SDICH-0969_20241220_2.2_STDsp.bin"
    # Remote path for BIOS firmware
    firmware_file_remote: "{{ remote_saa_linux_path }}/BIOS_A2SDICH-0969_20241220_2.2_STDsp.bin"
    # Required dependencies for SAA on Ubuntu
    saa_dependencies:
      - libssl-dev
      - libusb-1.0-0-dev
      - ipmitool
      - libncurses5-dev
    # RAID device to create
    raid_device: /dev/md127
    # RAID level (RAID 1 in this case)
    raid_level: 1
    # Disk devices to use for RAID array
    raid_devices:
      - /dev/sdb
      - /dev/sdc
    # Mount point for the new RAID device
    mount_point: /mnt/file_manager
    # Filesystem type for RAID device
    fs_type: ext4

  tasks:

    - name: Stop systemd-networkd-wait-online.service
      systemd:
        name: systemd-networkd-wait-online.service
        state: stopped
      become: yes

    - name: Disable auto-start of systemd-networkd-wait-online.service
      systemd:
        name: systemd-networkd-wait-online.service
        enabled: no
      become: yes

    - name: Mask systemd-networkd-wait-online.service
      command: systemctl mask systemd-networkd-wait-online.service
      become: yes

    - name: Replace Polish mirror with official Ubuntu mirror
      lineinfile:
        path: /etc/apt/sources.list
        regexp: 'pl.archive.ubuntu.com'
        line: 'deb http://archive.ubuntu.com/ubuntu {{ ansible_distribution_version }} main restricted universe multiverse'
        backrefs: yes
      become: yes
      notify: Update Ubuntu package cache

    - name: Clean outdated APT cache
      command: apt-get clean
      become: yes
      ignore_errors: yes

    - name: Remove local APT cache
      file:
        path: "/var/lib/apt/lists"
        state: absent
      become: yes

    - name: Create empty APT lists directory
      file:
        path: "/var/lib/apt/lists"
        state: directory
        mode: "0755"
        owner: root
        group: root
      become: yes

    - name: Update Ubuntu package cache (with retries)
      apt:
        update_cache: yes
        cache_valid_time: 3600
      become: yes
      register: apt_update_result
      until: apt_update_result is success
      retries: 5
      delay: 10
      when: ansible_distribution == 'Ubuntu' and ansible_distribution_version == '24.04'

    - name: Install required packages
      apt:
        name:
          - software-properties-common
          - mdadm
          - glances
          - nano
          - lm-sensors
          - htop
          - iputils-ping
          - openssh-server
        state: present
        update_cache: yes
      become: yes
      ignore_errors: yes

    - name: Install SAA dependencies for Ubuntu
      apt:
        name: "{{ saa_dependencies }}"
        state: present
        force_apt_get: yes
      become: yes
      when: ansible_distribution == 'Ubuntu' and ansible_distribution_version == '24.04'

    - name: Check presence of /dev/ipmi0 (Linux)
      stat:
        path: "/dev/ipmi0"
      register: ipmi_device_stat_linux
      when: ansible_facts.system == 'Linux'

    - name: Check if IPMI kernel modules are loaded
      shell: lsmod | grep ipmi
      register: ipmi_modules
      ignore_errors: yes
      changed_when: false
      when: ansible_facts.system == 'Linux'

    - name: Load IPMI kernel modules via modprobe
      shell: |
        modprobe ipmi_devintf
        modprobe ipmi_si
        modprobe ipmi_msghandler
      args:
        executable: /bin/bash
      become: yes
      when: >
        ansible_facts.system == 'Linux' and
        (ipmi_modules.stdout is not match("ipmi") or ipmi_device_stat_linux.stat.exists == false)

    - name: Check existence of parent dir /opt/supermicro
      stat:
        path: "/opt/supermicro"
      register: supermicro_dir_stat
      when: ansible_facts.system == 'Linux'

    - name: Create /opt/supermicro if missing
      file:
        path: "/opt/supermicro"
        state: directory
        mode: "0755"
        owner: "root"
        group: "root"
      become: yes
      when: >
        ansible_facts.system == 'Linux' and
        not supermicro_dir_stat.stat.exists

    - name: Remove old {{ remote_saa_linux_path }} dir (Linux)
      file:
        path: "{{ remote_saa_linux_path }}"
        state: absent
      become: yes
      when: ansible_facts.system == 'Linux'

    - name: Create {{ remote_saa_linux_path }} dir (Linux)
      file:
        path: "{{ remote_saa_linux_path }}"
        state: directory
        mode: "0755"
        owner: "root"
        group: "root"
      become: yes
      register: saa_dir_result_linux
      when: ansible_facts.system == 'Linux'

    - name: Confirm existence of {{ remote_saa_linux_path }}
      stat:
        path: "{{ remote_saa_linux_path }}"
      register: saa_dir_check
      until: saa_dir_check.stat.exists
      retries: 5
      delay: 1
      when: ansible_facts.system == 'Linux'

    - name: Copy SAA_Linux from controller to remote host (Linux)
      copy:
        src: "{{ local_saa_linux_path }}/saa"
        dest: "{{ remote_saa_linux_path }}/"
        mode: "0755"
        owner: "root"
        group: "root"
        force: yes
      become: yes
      register: saa_copy_result_linux
      when: ansible_facts.system == 'Linux' and saa_dir_check.stat.exists

    - name: Copy BIOS firmware file to remote host
      copy:
        src: "{{ firmware_file_local }}"
        dest: "{{ firmware_file_remote }}"
        mode: "0644"
        owner: "root"
        group: "root"
      become: yes
      register: firmware_copy_result
      when: ansible_facts.system == 'Linux'

    - name: Check if SAA executable exists
      stat:
        path: "{{ remote_saa_linux_path }}/saa"
      register: saa_executable_check
      when: ansible_facts.system == 'Linux'

    - name: Set executable permissions for SAA binary (Linux)
      file:
        path: "{{ remote_saa_linux_path }}/saa"
        mode: "0755"
      become: yes
      register: saa_exec_result_linux
      when: >
        ansible_facts.system == 'Linux' and
        saa_executable_check.stat.exists and
        saa_copy_result_linux is success

    - name: Update BIOS using SAA (Linux)
      shell: |
        cd {{ remote_saa_linux_path }}
        ./saa -c UpdateBios --file {{ firmware_file_remote }}
      args:
        executable: /bin/bash
        chdir: "{{ remote_saa_linux_path }}"
      register: saa_update_linux
      ignore_errors: no
      no_log: false
      become: yes
      when: >
        ansible_facts.system == 'Linux' and
        firmware_copy_result is success

    - name: Reboot server after BIOS update
      reboot:
        msg: "Rebooting server after BIOS update"
        reboot_timeout: 600
      when: saa_update_linux is success
      become: yes

    - name: Check existence of mount point {{ mount_point }}
      stat:
        path: "{{ mount_point }}"
      register: mount_point_stat
      changed_when: false

    - name: Unmount existing mount point {{ mount_point }}
      mount:
        path: "{{ mount_point }}"
        state: unmounted
      when: mount_point_stat.stat.exists

    - name: Delete directory {{ mount_point }}
      file:
        path: "{{ mount_point }}"
        state: absent
      when: mount_point_stat.stat.exists

    - name: Stop and remove old RAID arrays
      shell: |
        for array in $(cat /proc/mdstat | grep -Eo 'md[0-9]+'); do
          umount "/dev/$array" || true
          mdadm --stop "/dev/$array" || true
          mdadm --remove "/dev/$array" || true
        done
      become: yes
      ignore_errors: yes

    - name: Clear superblocks from disks
      shell: |
        mdadm --zero-superblock {{ item }} || true
        wipefs -a {{ item }} || true
      loop: "{{ raid_devices }}"
      become: yes
      ignore_errors: yes

    - name: Reread partition tables
      shell: |
        partprobe {{ item }}
        blockdev --rereadpt {{ item }} || true
      loop: "{{ raid_devices }}"
      become: yes

    - name: Create RAID1 array named md127
      shell: |
        yes | mdadm --create /dev/md127 \
          --level=1 \
          --raid-devices=2 \
          --metadata=1.2 \
          --name=127 \
          {{ raid_devices[0] }} {{ raid_devices[1] }} \
          --force --assume-clean
      args:
        creates: /dev/md127
      become: yes

    - name: Asynchronous check for RAID sync completion
      shell: |
        while grep -E 'resync|recovery|reshape|check' /proc/mdstat > /dev/null; do
          echo -e "\e[33mRAID synchronization active...\e[0m"
          cat /proc/mdstat | grep -E 'resync|recovery|reshape|check' | awk '{print "\e[36m" $0 "\e[0m"}'
          sleep 10
        done
        echo -e "\e[32mRAID synchronization complete.\e[0m"
      async: 3600
      poll: 10
      changed_when: false

    - name: Update mdadm.conf with current array details
      shell: mdadm --detail --scan > /etc/mdadm/mdadm.conf
      become: yes

    - name: Uncomment DEVICE partitions containers line
      lineinfile:
        path: /etc/mdadm/mdadm.conf
        regexp: '^#DEVICE partitions containers'
        line: 'DEVICE partitions containers'
        backrefs: yes
        create: no
      become: yes

    - name: Add raid1 module to initramfs
      lineinfile:
        path: /etc/initramfs-tools/modules
        line: raid1
        create: yes
        mode: '0644'
      become: yes

    - name: Update initramfs
      command: update-initramfs -u -k all
      become: yes

    - name: Get UUID of RAID device dynamically
      command: blkid -s UUID -o value /dev/md127
      register: raid_uuid
      changed_when: false
      become: yes

    - name: Update fstab with new UUID
      lineinfile:
        path: /etc/fstab
        regexp: '\s{{ mount_point }}\s'
        line: "UUID={{ raid_uuid.stdout }} {{ mount_point }} {{ fs_type }} defaults,nofail,x-systemd.device-timeout=30 0 2"
        create: yes
        mode: '0644'
      become: yes

    - name: Create ext4 filesystem
      filesystem:
        fstype: "{{ fs_type }}"
        dev: "{{ raid_device }}"

    - name: Create mount point directory
      file:
        path: "{{ mount_point }}"
        state: directory
        mode: '0755'

    - name: Set owner and group for {{ mount_point }}
      file:
        path: "{{ mount_point }}"
        owner: player
        group: player
        recurse: yes
      become: yes

    - name: Set permissions for {{ mount_point }}
      file:
        path: "{{ mount_point }}"
        mode: '0755'
        recurse: yes
      become: yes

    - name: Update fstab again
      lineinfile:
        path: /etc/fstab
        regexp: '\s{{ mount_point }}\s'
        line: "UUID={{ raid_uuid.stdout }} {{ mount_point }} {{ fs_type }} defaults,nofail,x-systemd.device-timeout=30 0 2"
        create: yes
        mode: '0644'
      ignore_errors: yes

    - name: Reboot system
      reboot:
        msg: "Rebooting to apply RAID changes"
        reboot_timeout: 600

    - name: Wait for connection after reboot
      wait_for_connection:
        timeout: 300

    - name: Check RAID status after reboot
      shell: cat /proc/mdstat
      register: mdstat_after_reboot
      until: "'active raid1' in mdstat_after_reboot.stdout"
      retries: 20
      delay: 3

    - name: Print final RAID status
      debug:
        msg: "{{ mdstat_after_reboot.stdout }}"

    - name: Final step - power off the host
      ansible.builtin.command: poweroff
      become: true
```

---

Ten plik to **playbook Ansible** przeznaczony do zdalnej, w pełni zautomatyzowanej konfiguracji serwera z systemem Ubuntu 24.04. Obejmuje szereg zadań niezbędnych do przygotowania serwera do pracy w środowisku produkcyjnym.

#### Główne funkcje:

* **Zarządzanie siecią:**
  Wyłączenie usługi `systemd-networkd-wait-online`, mogącej powodować opóźnienia przy starcie systemu.

* **Aktualizacja repozytoriów:**
  Zmiana lokalnego mirrora na oficjalny globalny serwer Ubuntu w celu zapewnienia stabilniejszych i szybszych aktualizacji.

* **Instalacja zależności:**
  Instalacja niezbędnych pakietów i bibliotek do działania narzędzi sprzętowych (w tym Supermicro SAA).

* **Obsługa IPMI:**
  Weryfikacja i aktywacja modułów jądra odpowiedzialnych za zdalne zarządzanie serwerem (IPMI).

* **Zdalna aktualizacja BIOS-u:**
  Transfer i uruchomienie narzędzia Supermicro SAA wraz z plikiem firmware, umożliwiające bezobsługową aktualizację BIOS-u.

* **Konfiguracja RAID 1:**
  Usunięcie wcześniejszych konfiguracji, czyszczenie dysków `/dev/sdb` i `/dev/sdc`, a następnie utworzenie macierzy `RAID 1`.

* **System plików i montowanie:**
  Formatowanie nowej macierzy jako `ext4`, konfiguracja punktu montowania `/mnt/file_manager`, ustawienie właściciela (`player`) oraz odpowiednich uprawnień.

* **Konfiguracja rozruchu:**
  Aktualizacja pliku `/etc/mdadm/mdadm.conf`, regeneracja `initramfs`, konfiguracja `fstab` z UUID nowej macierzy.

* **Kontrolowane restarty i testy:**
  Weryfikacja poprawnego działania RAID po każdym restarcie.

* **Zakończenie:**
  Po zakończeniu wszystkich operacji system jest wyłączany.

---

### Zastosowanie:

Ten playbook umożliwia szybkie, powtarzalne i spójne wdrożenie wielu serwerów z identyczną konfiguracją sprzętowo-programową.
