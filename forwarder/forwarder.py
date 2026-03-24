"""
forwarder/forward.py

하위 호환 wrapper.
기존 코드에서 from forwarder.forward import forward 를 사용하는 경우를 위해 유지.
내부적으로 live_sink.send 를 재사용한다.
"""

from forwarder.live_sink import send as forward

__all__ = ["forward"]