"""提供命令行入口，使工具可以通过 `python -m src.ac_ir_tool` 直接启动。"""

from .cli import main


if __name__ == "__main__":
    raise SystemExit(main())
