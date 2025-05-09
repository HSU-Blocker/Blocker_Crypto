import re

class PolicyService:
    @staticmethod
    def build_attribute_policy(policy_dict):
        """
        policy_dict에서 각 속성별 논리식을 파싱하여 AND로 결합된 전체 접근 정책 문자열을 생성
        예: {"model": "A OR B", "serial": "1234"} → "(A or B) and (1234)"
        """
        # 필수 속성 검사
        required_keys = ["model", "serial"]
        for key in required_keys:
            if key not in policy_dict or not policy_dict[key].strip():
                raise ValueError(f"'{key}' 속성은 필수입니다.")

        def parse_expression(expr: str) -> str:
            expr = expr.strip()
            expr = expr.replace("AND", "and").replace("OR", "or")
            expr = re.sub(r"\s+", " ", expr)  # 중복 공백 제거
            return expr

        expressions = []
        for key, value in policy_dict.items():
            if value.strip():
                parsed = parse_expression(value)
                expressions.append(f"({parsed})")

        full_policy = " and ".join(expressions)
        return full_policy
