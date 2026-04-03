# 安装

Speakeasy 需要 Python 3.10+。

## Python 3.12+ 特别说明

如果您使用 Python 3.12 或更高版本，请确保安装最新版本的依赖库，特别是 `unicorn` 库（需要 2.1.4 或更高版本），因为旧版本依赖已被移除的 `distutils` 模块。

推荐在虚拟环境中安装：

```console
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

pip install --upgrade pip
pip install -e ".[dev]"
```

## 从 PyPI 安装

```console
python3 -m pip install speakeasy-emulator
```

可选的 GDB 支持：

```console
python3 -m pip install "speakeasy-emulator[gdb]"
```

验证安装：

```console
speakeasy -h
```

## 从源代码安装

```console
git clone https://github.com/mandiant/speakeasy.git
cd speakeasy
python3 -m pip install -e ".[dev]"
```

从源代码安装可选的 GDB 支持：

```console
python3 -m pip install -e ".[dev,gdb]"
```

## 相关文档

- [项目 README](../README.md)
- [文档索引](index.md)
- [命令行参考](cli-reference.md)
- [帮助和故障排除](help.md)