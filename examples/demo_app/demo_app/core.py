"""示例业务代码（确定性的，本身没有非确定源）。"""


def greet(name: str) -> str:
    return f"hello, {name}"


def fib(n: int) -> int:
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a
