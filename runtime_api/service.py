"""
runtime_api/service.py  (updated)

기존 로직은 services/workload_detail.py 로 이전했다.
이 파일은 하위 호환 shim 역할만 한다.
routers/workloads.py 가 이 파일을 import 하고 있으므로 시그니처 유지.
"""
from runtime_api.services.workload_detail import (  # noqa: F401
    build_summary,
    get_workload_detail,
    list_workloads,
)
