audit_results = []

total_audits = len(audit_results)
vulnerable_count = sum(1 for r in audit_results if r['status'] == 'VULNERABLE')



report_summary = {
    "총 점검 항목": total_audits,
    "취약 항목": vulnerable_count,
    "양호 항목": total_audits - vulnerable_count
}

print("\n--- 점검 요약 ---")
for key, value in report_summary.items():
    print(f"{key}: {value}")
print("\n")

        # 위험도 및 분류 항목별 취약점 개수 초기화
risk_levels = ["상", "중", "하", "총계"]
categories_for_display = [
    "계정 관리",
    "파일 및 디렉터리 관리",
    "서비스 관리",
    "패치 관리",
    "로그 관리",
    "총계"
]

# 모든 위험도-분류 항목 조합에 대해 0으로 초기화
vulnerability_counts = {
    risk: {category: 0 for category in categories_for_display}
    for risk in risk_levels
}

os_type = "Windows"
import json
with open("audit_config.json", 'r', encoding='utf-8') as f:
    config = json.load(f)

with open("./audit_reports/security_audit_report_Windows_20250804_095056.json", 'r', encoding='utf-8') as f:
    audit_results = json.load(f)

platform_specific_config = config.get(os_type, {})

# 각 점검 항목의 U-XX 코드를 추출하고 위험도 및 분류에 따라 분류합니다. ■■■■■■■■■■■■■■■수정■■■■■■■■■■■■■
for result in audit_results:
    if result['status'] == 'VULNERABLE':
        item_name = result.get('item', '')
        # 'U-XX. 항목 이름' 형식에서 'U-XX' 부분만 추출
        u_code = item_name.split('.')[0].strip()

        risk_level = config.get(os_type,{}).get("RISK_LEVEL_MAPPING").get(u_code)
        category = config.get(os_type,{}).get("CATEGORY_MAPPING").get(u_code)
        
        if risk_level and category and risk_level in risk_levels and category in categories_for_display:
            vulnerability_counts[risk_level][category] += 1
        # else:
            # 매핑에 없는 항목은 무시하거나, 필요에 따라 로깅할 수 있습니다.
            # logging.warning(f"경고: 알 수 없는 U-XX 코드 '{u_code}'에 대한 위험도 또는 분류 정보가 없습니다.")

# 보고서 헤더 및 데이터 출력 (더 깔끔한 형식으로 변경)
# 각 분류 항목 헤더의 최대 너비 계산 (최소 10칸 확보)
# 헤더와 데이터의 최대 길이를 고려하여 너비를 동적으로 조정
col_widths = {cat: max(len(cat), 10) for cat in categories_for_display}

# '상/중/하' 열의 너비 설정
risk_label_width = 3 # "상", "중", "하" + 여백

# 헤더 출력
header_parts = [" " * risk_label_width] # 첫 번째 빈 칸
for cat in categories_for_display:
    header_parts.append(f"{cat:^{col_widths[cat]}}") # 중앙 정렬
print(" | ".join(header_parts))

# 구분선 출력
separator_parts = ["-" * risk_label_width]
for cat in categories_for_display:
    separator_parts.append("-" * (col_widths[cat] + 5))
print("-+-".join(separator_parts))


column_total = {category: 0 for category in categories_for_display}
# entire_total = 0
for risk in risk_levels:
    data_parts = [f"{risk:<{risk_label_width}}"] # 좌측 정렬
    row_total = 0 # 각 행의 합계를 저장할 변수 초기화
    for category in categories_for_display:
        if risk != "총계" :
            if category != "총계" :
                count = vulnerability_counts[risk][category]
                data_parts.append(f"{str(count):^{col_widths[category]}}") # 중앙 정렬
                row_total += count # 현재 카테고리의 값을 행의 합계에 더합니다.
            else:
                data_parts.append(f"{str(row_total):^{col_widths[category]}}")
                vulnerability_counts[risk][category] = row_total
            column_total[category] += vulnerability_counts[risk][category] # 컬럼 합 계산
        else:
            data_parts.append(f"{str(column_total[category]):^{col_widths[category]}}")
    
    # entire_total += row_total
    print("  |    ".join(data_parts))