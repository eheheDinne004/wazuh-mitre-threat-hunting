#  Threat Hunting & Detection Engineering with Wazuh SIEM & MITRE ATT&CK

> **Đề tài:** Xây dựng hệ thống giám sát, phân tích nhật ký và săn lùng mối đe dọa sử dụng Wazuh SIEM và Khung chuẩn MITRE ATT&CK

![Wazuh](https://img.shields.io/badge/SIEM-Wazuh-blue)
![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red)
![Sysmon](https://img.shields.io/badge/Sensor-Sysmon-green)
![Logs](https://img.shields.io/badge/Analysis-Event%20Viewer-orange)

---

##  Tổng quan dự án (Overview)

Dự án tập trung vào kỹ thuật **Detection Engineering** và **Threat Hunting chủ động**, nghiên cứu cơ chế thu thập, bóc tách dữ liệu nhật ký (log) thô và chuyển hóa thành các cảnh báo bảo mật có ngữ cảnh. 

Trọng tâm của dự án là việc thiết kế các bộ luật phát hiện tùy chỉnh (**Custom Rules**) trên nền tảng **Wazuh SIEM**, đồng thời **chuẩn hóa và ánh xạ từng cảnh báo lên Ma trận MITRE ATT&CK** nhằm hỗ trợ đội ngũ SOC dễ dàng định vị hành vi của tác nhân đe dọa.

---

##  Kiến trúc Luồng Xử lý Log (Log Pipeline Architecture)

```text
[ Windows Endpoint ] 
   └── Sysmon / Windows Event Logs (Event ID 4688, 4625, 3, v.v.)
         │
         ▼ (Encrypted Log Transport)
[ Wazuh Agent ]
         │
         ▼
[ Wazuh Manager / SIEM ]
   ├── Log Analysis & Decoders (Bóc tách chuỗi log thô)
   ├── Custom Rules Engine (Khớp các quy tắc phát hiện)
   └── MITRE ATT&CK Mapping (Gắn nhãn Tactic & Technique)
         │
         ▼
[ Wazuh Dashboard ] ──> Cảnh báo trực quan hóa & Phân tích sự cố (SOC)
```

---

##  Bảng Ánh xạ Khung MITRE ATT&CK & Bộ Luật Phát hiện (Rule Detection)

Hệ thống được thiết lập để giám sát và gán nhãn chính xác các kỹ thuật tấn công phổ biến theo chuẩn **MITRE Enterprise Matrix**:

| MITRE Tactic | MITRE Technique / Sub-technique | Event ID / Nguồn Log | Rule ID (Wazuh) | Mức độ Cảnh báo |
| :--- | :--- | :--- | :---: | :---: |
| **Initial Access** | Brute Force: Password Guessing (`T1110.001`) | Windows Security (ID `4625`) | `100071` |  Level 12 |
| **Execution** | User Execution: Malicious File (`T1204.002`) | Sysmon Process Create (ID `1`) | `100078` |  Level 12 |
| **Defense Evasion** | Obfuscated Files or Information (`T1027`) | Sysmon File Creation (ID `11`) | `100079` |  Level 10 |
| **Persistence / Exec** | Command and Scripting Interpreter (`T1059`) | Windows Audit / Sysmon (ID `1`) | `100080` | Level 12 |

---

##  Cấu hình Luật Wazuh tùy chỉnh (Custom Wazuh Rules Example)

Tất cả các luật phát hiện đều được viết bằng XML cấu trúc chuẩn của Wazuh, tích hợp trực tiếp thẻ `<mitre>` để tự động hiển thị lên Dashboard.

Ví dụ đoạn cấu hình ánh xạ MITRE ATT&CK trong `local_rules.xml`:

```xml
<group name="sysmon, threat_hunting,">
  <rule id="100078" level="12">
    <if_sid>61603</if_sid>
    <field name="win.eventdata.image">\\AppData\\Local\\Temp\\|\\Downloads\\</field>
    <description>Threat Hunting: Execution detected from suspicious directory</description>
    <mitre>
      <id>T1204.002</id>
    </mitre>
  </rule>
</group>
```

---

##  Cấu trúc Repository (Repo Structure)

```text
.
├── rules/                     # Tập hợp các bộ quy tắc phát hiện & cấu hình
│   ├── local_rules.xml        # Cấu hình Wazuh Custom Rules + MITRE Tags
│   └── sysmonconfig.xml       # File cấu hình cảm biến Sysmon tối ưu cho Wazuh
├── docs/                      # Báo cáo, tài liệu hướng dẫn & hình ảnh minh họa
│   ├── Threat_Hunting_Report.pdf
│   └── mitre_dashboard_demo.png
└── README.md                  # Document hướng dẫn dự án
```

---

##  Hướng dẫn Triển khai (Deployment)

1. **Cấu hình Sysmon:** Cài đặt Sysmon trên máy giám sát sử dụng file cấu hình `rules/sysmonconfig.xml`.
2. **Import Custom Rules:** Trích xuất file `rules/local_rules.xml` và dán vào thư mục quy tắc của Wazuh Manager:
   ```bash
   /var/ossec/etc/rules/local_rules.xml
   ```
3. **Restart Wazuh Manager:**
   ```bash
   sudo systemctl restart wazuh-manager
   ```
4. **Kiểm tra Dashboard:** Truy cập giao diện Wazuh Dashboard -> Mục **MITRE ATT&CK** để theo dõi các sự kiện được phân loại theo Tactic và Technique realtime.

---
